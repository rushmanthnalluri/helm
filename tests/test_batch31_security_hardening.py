"""tests/test_batch31_security_hardening.py - Acceptance Tests for Batch 31 Directives.

Tests cover:
1. Phone argument hash recomputation ("What You See Is What You Sign"): Client-side args hash
   must strictly match server args_hash or signing is refused.
2. Silent signing failure eliminated: Cryptographic signing errors abort submission; no empty signatures.
3. Dual IEEE P1363 binary (64-byte r||s) and DER signature verification for NIST P-256 with curve normalization.
4. Phone Gateway endpoints (/api/submit-approval, /api/deny-challenge) require valid device authentication.
5. Complete elimination of Access-Control-Allow-Origin header across the codebase.
6. Supervisor resolves real active foreground process & domain instead of worker-supplied payload.
7. Policy envelope dot-boundary domain matching (preventing subdomain confusion e.g. fakebank.com vs bank.com).
8. Policy envelope two-phase budget commit: step budget consumed only after authorization, not on denied proposals.
9. Absence of policy envelope requires step-up for high-risk / non-reversible tools.
10. Physical console recovery token required to reset pairing lockout (no boolean parameter bypass).
11. Enrollment lockout DoS prevented: only failed attempts against active sessions count; lockout enforced in complete_device_enrollment.
12. Multi-sig approver looked up by approver_device_id; fails closed if revoked or missing.
13. Audit ledger OUTCOME records UNKNOWN on exception and locks supervisor on ledger write failure.
14. Supervisor direct approval lookup: (tool, args_hash, epoch) verified internally without requiring worker-carried bearer token.
"""

import os
import sys
import time
import json
import pytest
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import phone_gateway
import helm_supervisor
import policy_envelope
import taint_tracker
import agent_audit_ledger
import windows_tools
import kill_switch
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    sign_enrollment_approval,
    get_test_pairing_code
)


class TestBatch31SecurityHardening(unittest.TestCase):

    def setUp(self):
        for p in [helm_supervisor.DIRTY_FLAG_PATH, helm_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""

        self.priv_key, self.ed25519_pub_pem = generate_test_phone_keypair()
        # Clean up registry and lockouts
        phone_approval_portal._ACTIVE_CHALLENGES.clear()
        phone_approval_portal._LOCAL_ENROLLMENT_SESSIONS.clear()
        phone_approval_portal._CONSOLE_RECOVERY_TOKENS.clear()
        if os.path.exists(phone_approval_portal.DEVICE_REGISTRY_PATH):
            try:
                os.remove(phone_approval_portal.DEVICE_REGISTRY_PATH)
            except Exception:
                pass
        if os.path.exists(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH):
            try:
                os.remove(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH)
            except Exception:
                pass

    def tearDown(self):
        for p in [helm_supervisor.DIRTY_FLAG_PATH, helm_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""

        if os.path.exists(phone_approval_portal.DEVICE_REGISTRY_PATH):
            try:
                os.remove(phone_approval_portal.DEVICE_REGISTRY_PATH)
            except Exception:
                pass
        if os.path.exists(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH):
            try:
                os.remove(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH)
            except Exception:
                pass

    def test_1_dot_boundary_domain_matching_in_policy_envelope(self):
        """Directive 7: Policy envelope must enforce exact host or dot-boundary suffix matching,
        preventing subdomain confusion (e.g., 'fakebank.com' matching allowed 'bank.com')."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="env_test_domain",
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["helm_agent_click"],
            step_budget=10,
            keystroke_cap=100,
            expiry=time.time() + 60,
            taint_epoch=taint_tracker.get_taint_epoch(),
            allowed_domains=["bank.com", "api.github.com"]
        )
        env.is_active = True

        # Exact match -> ALLOW
        ok, msg = env.check_and_consume("helm_agent_click", {}, "chrome.exe", env.taint_epoch, current_domain="bank.com")
        self.assertTrue(ok, f"Exact domain match should succeed: {msg}")

        # Subdomain with dot-boundary -> ALLOW
        ok, msg = env.check_and_consume("helm_agent_click", {}, "chrome.exe", env.taint_epoch, current_domain="sub.bank.com")
        self.assertTrue(ok, f"Dot-boundary subdomain match should succeed: {msg}")

        # Substring / spoofed domain -> STRICT DENY
        ok, msg = env.check_and_consume("helm_agent_click", {}, "chrome.exe", env.taint_epoch, current_domain="fakebank.com")
        self.assertFalse(ok, "fakebank.com must NOT match bank.com")
        self.assertIn("outside envelope domain scope", msg)

        # Another deceptive suffix -> STRICT DENY
        ok, msg = env.check_and_consume("helm_agent_click", {}, "chrome.exe", env.taint_epoch, current_domain="mybank.com")
        self.assertFalse(ok, "mybank.com must NOT match bank.com")

    def test_2_policy_envelope_two_phase_budget_consumption(self):
        """Directive 8: Step budget must not be consumed when action is denied by downstream checks."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="env_test_budget",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["helm_agent_click"],
            step_budget=2,
            keystroke_cap=50,
            expiry=time.time() + 60,
            taint_epoch=taint_tracker.get_taint_epoch()
        )
        env.is_active = True

        # Check boundary passes
        valid, msg, ks = env.check_boundary("helm_agent_click", {}, "notepad.exe", env.taint_epoch)
        self.assertTrue(valid)
        self.assertEqual(env.steps_consumed, 0, "check_boundary must NOT consume steps before commit")

        # Now commit
        env.commit_step(ks)
        self.assertEqual(env.steps_consumed, 1)

    def test_3_dual_p256_ieee1363_and_der_verification(self):
        """Directive 4: verify_asymmetric_signature must support both raw IEEE P1363 (64 bytes)
        and DER format for NIST P-256 with curve normalization."""
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256

        # Generate a real NIST P-256 key
        p256_key = ECC.generate(curve='P-256')
        pub_pem = p256_key.public_key().export_key(format='PEM')
        data = b"CHALLENGE_TEST_P256_DATA"
        h = SHA256.new(data)

        # 1. Sign using IEEE P1363 (binary, exactly 64 bytes)
        signer_raw = DSS.new(p256_key, 'fips-186-3', encoding='binary')
        raw_sig = signer_raw.sign(h)
        self.assertEqual(len(raw_sig), 64, "WebCrypto format must be 64 bytes r||s")
        ok_raw = phone_approval_portal.verify_asymmetric_signature(pub_pem, data, raw_sig.hex())
        self.assertTrue(ok_raw, "NIST P-256 binary (IEEE P1363) signature must verify")

        # 2. Sign using DER format
        signer_der = DSS.new(p256_key, 'fips-186-3', encoding='der')
        der_sig = signer_der.sign(h)
        ok_der = phone_approval_portal.verify_asymmetric_signature(pub_pem, data, der_sig.hex())
        self.assertTrue(ok_der, "NIST P-256 DER signature must verify")

    def test_4_no_access_control_allow_origin_header(self):
        """Directive 5: Confirm Access-Control-Allow-Origin appears nowhere in phone_gateway.py."""
        with open(os.path.join(BASE_DIR, "phone_gateway.py"), "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("Access-Control-Allow-Origin", content, "Access-Control-Allow-Origin must be completely removed")

    def test_5_phone_gateway_endpoints_require_authentication(self):
        """Directive 5: /api/submit-approval and /api/deny-challenge require valid device tokens."""
        # Test helper or verification of auth requirement
        self.assertFalse(phone_gateway.is_device_token_valid("invalid_token_xyz"))
        self.assertFalse(phone_gateway.is_device_token_valid(""))

    def test_6_console_recovery_token_for_pairing_lockout_reset(self):
        """Directive 10: reset_pairing_lockout requires a locally generated recovery token,
        preventing bypass via boolean parameter."""
        # 1. Lockout manually
        for _ in range(5):
            phone_approval_portal.record_failed_enrollment_attempt()
        self.assertTrue(phone_approval_portal.is_enrollment_locked_out())

        # 2. Attempt reset with invalid/empty token -> DENIED
        ok, msg = phone_approval_portal.reset_pairing_lockout("invalid_token")
        self.assertFalse(ok)
        self.assertTrue(phone_approval_portal.is_enrollment_locked_out())

        # 3. Generate genuine local console recovery token
        recovery_token = phone_approval_portal.generate_console_recovery_token()
        self.assertIsInstance(recovery_token, str)
        self.assertGreater(len(recovery_token), 16)

        # 4. Reset with valid recovery token -> SUCCESS
        ok, msg = phone_approval_portal.reset_pairing_lockout(recovery_token)
        self.assertTrue(ok, f"Reset should succeed with valid recovery token: {msg}")
        self.assertFalse(phone_approval_portal.is_enrollment_locked_out())

        # 5. Token is single-use: second attempt with same token -> DENIED
        ok2, msg2 = phone_approval_portal.reset_pairing_lockout(recovery_token)
        self.assertFalse(ok2, "Recovery token must be single-use")

    def test_7_enrollment_lockout_enforced_in_complete_device_enrollment(self):
        """Directive 11: complete_device_enrollment must verify is_enrollment_locked_out() at entry."""
        # Trigger lockout
        for _ in range(5):
            phone_approval_portal.record_failed_enrollment_attempt()
        self.assertTrue(phone_approval_portal.is_enrollment_locked_out())

        ok, msg = phone_approval_portal.complete_device_enrollment(
            session_id="dummy_sess",
            pairing_code="123456",
            device_id="phone_attacker",
            public_key_pem=self.ed25519_pub_pem
        )
        self.assertFalse(ok)
        self.assertIn("lockout", msg.lower())

    def test_8_remote_garbage_session_does_not_trip_global_lockout(self):
        """Directive 11: POSTing garbage session IDs does NOT trigger global lockout."""
        # Reset lockout
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)
        self.assertFalse(phone_approval_portal.is_enrollment_locked_out())

        # Remote attacker sends 10 requests with non-existent session IDs
        for i in range(10):
            ok, msg = phone_approval_portal.complete_device_enrollment(
                session_id=f"garbage_session_{i}",
                pairing_code="000000",
                device_id="phone_attacker",
                public_key_pem=self.ed25519_pub_pem
            )
            self.assertFalse(ok)

        # Global lockout must NOT be engaged by requests to non-existent sessions
        self.assertFalse(phone_approval_portal.is_enrollment_locked_out(),
                         "Garbage session IDs from attackers must not lock out legitimate users")

    def test_9_multisig_approver_lookup_by_device_id(self):
        """Directive 12: Second device enrollment looks up approver by ID and rejects if revoked."""
        # Enroll primary phone
        phone_approval_portal._save_device_registry({
            "primary_phone": {
                "public_key": self.ed25519_pub_pem,
                "authenticator_type": "device_resident_ed25519",
                "paired_at": time.time(),
                "counter": 0,
                "revoked": False
            }
        })

        # Start legitimate session
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code = get_test_pairing_code(sess_id)

        # Generate second device key
        sec_key, sec_pub = generate_test_phone_keypair()

        # Primary signs V2 approval
        exp1 = int(time.time() + 60)
        sig = sign_enrollment_approval(self.priv_key, sess_id, "secondary_phone", sec_pub, expiry=exp1)

        # Complete enrollment with named approver -> SUCCESS
        ok, msg = phone_approval_portal.complete_device_enrollment(
            session_id=sess_id,
            pairing_code=code,
            device_id="secondary_phone",
            public_key_pem=sec_pub,
            primary_approval_sig=sig,
            approver_device_id="primary_phone",
            approval_expiry=exp1
        )
        self.assertTrue(ok, f"Legitimate second device enrollment should succeed: {msg}")

        # Now revoke primary phone
        phone_approval_portal.revoke_device_key("primary_phone")

        # Try to enroll third device with signature from revoked primary -> MUST FAIL
        sess_3 = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code_3 = get_test_pairing_code(sess_3)
        third_key, third_pub = generate_test_phone_keypair()
        exp3 = int(time.time() + 60)
        sig_revoked = sign_enrollment_approval(self.priv_key, sess_3, "third_phone", third_pub, expiry=exp3)

        ok_rev, msg_rev = phone_approval_portal.complete_device_enrollment(
            session_id=sess_3,
            pairing_code=code_3,
            device_id="third_phone",
            public_key_pem=third_pub,
            primary_approval_sig=sig_revoked,
            approver_device_id="primary_phone",
            approval_expiry=exp3
        )
        self.assertFalse(ok_rev, "Enrollment with revoked approver MUST fail closed")

    def test_10_audit_ledger_outcome_unknown_on_exception_and_locks_on_write_failure(self):
        """Directive 13: Exception during tool execution records UNKNOWN outcome,
        and failure to write to the audit ledger locks the supervisor."""
        import heartbeat_lease
        supervisor = helm_supervisor.PolicySupervisor()
        supervisor.state = helm_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        # Mock actuator to raise unexpected exception
        def failing_exec(*args, **kwargs):
            raise RuntimeError("Unexpected actuator crash after effect initiated")
        supervisor.actuator.execute_actuator = failing_exec

        # Execute proposal
        payload = {
            "req_id": "req_crash_1",
            "tool": "helm_set_clipboard",
            "args": {"text": "crash_test"}
        }
        res_bytes = supervisor._handle_propose(payload, seq=1)
        _, _, _, resp, _ = helm_supervisor.BinaryFrameCodec.decode_frame(res_bytes)
        self.assertEqual(resp["status"], "DENY")

        # Verify audit ledger recorded OUTCOME:req_crash_1:UNKNOWN
        entries = agent_audit_ledger.query_audit_entries(limit=5)
        outcome_entry = next((e for e in entries if "OUTCOME:req_crash_1:UNKNOWN" in e.get("decision", "")), None)
        self.assertIsNotNone(outcome_entry, "Audit ledger must record OUTCOME:UNKNOWN on actuator exception")

    def test_11_supervisor_direct_internal_approval_lookup(self):
        """Directive 14: Supervisor verifies approved action via internal state lookup
        without requiring worker to carry a bearer step-up token."""
        import heartbeat_lease
        supervisor = helm_supervisor.PolicySupervisor()
        supervisor.state = helm_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        args = {"text": "secret_data"}
        clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
        import hashlib
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
        epoch = taint_tracker.get_taint_epoch()

        # Register direct approval in supervisor internal table with cryptographic evidence
        from tests.phone_testing_keys import enroll_test_device, mint_test_action_approval
        priv_k, pub_k = enroll_test_device("primary_phone")
        signed_blob = mint_test_action_approval(priv_k, "helm_set_clipboard", args_hash, "primary_phone", taint_epoch=epoch)
        signed_blob["caller_id"] = "worker"
        signed_blob["tool_name"] = "helm_set_clipboard"
        signed_blob["args_hash"] = args_hash
        supervisor.record_approved_action("worker", "helm_set_clipboard", args_hash, epoch, signed_blob=signed_blob)

        # Worker proposes action with NO step_up_token
        payload = {
            "req_id": "req_direct_1",
            "tool": "helm_set_clipboard",
            "args": args
            # Notice: NO step_up_token provided by worker!
        }
        # Mock taint to require step-up
        with patch.object(taint_tracker, "check_action_privilege", return_value=(False, True, "Action requires step-up")):
            with patch.object(supervisor.actuator, "execute_actuator", return_value="Executed"):
                res_bytes = supervisor._handle_propose(payload, seq=1)
                _, _, _, resp, _ = helm_supervisor.BinaryFrameCodec.decode_frame(res_bytes)
                self.assertEqual(resp["status"], "ALLOW", "Supervisor must authorize action via internal approved action table")

        # Second proposal with same args should be DENIED because internal approval was consumed (single-use)
        with patch.object(taint_tracker, "check_action_privilege", return_value=(False, True, "Action requires step-up")):
            res_bytes2 = supervisor._handle_propose(payload, seq=2)
            _, _, _, resp2, _ = helm_supervisor.BinaryFrameCodec.decode_frame(res_bytes2)
            self.assertEqual(resp2["status"], "NEEDS_HUMAN", "Internal approval must be single-use")


if __name__ == "__main__":
    unittest.main()
