"""tests/test_batch30_security_hardening.py - Batch 30 Defense Hardening Acceptance Suite.

Test-Driven Verification for:
1. Supervisor Fail-Open Fix: Strict DENY when action privilege returns (False, False) (non-stepup taint deny).
2. Supervisor Strict Dict Argument Validation: Non-dict args rejected immediately with REASON_MALFORMED_FRAME.
3. Supervisor Envelope Enforcement: PolicyEnvelope domain scoping & step limits checked inside _handle_propose.
4. Supervisor Outcome Audit Invariant: OUTCOME ledger entry is guaranteed even on execution exception (in finally block).
5. Enrollment Multi-Sig Revoked Primary Bypass Prevention: Active non-revoked device approval is required even if primary is revoked.
6. Enrollment Multi-Sig Session & Expiry Binding (V2): Signature binds session_id, device_id, pem, and expiry.
7. Global Persistent Enrollment Lockout: Failed pairing attempts across sessions persist and lock out after threshold.
8. Gateway Host & Origin DNS Rebinding Protection: Rejects foreign Host and untrusted Origin headers (no wildcard CORS).
9. Gateway Deny Challenge Endpoint: POST /api/deny-challenge purges challenge on server.
10. Dual ECDSA P-256 and Ed25519 Support: Supports WebCrypto P-256 signatures from standard mobile browsers.
"""

import os
import sys
import time
import json
import unittest
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import homie_supervisor
import phone_gateway
import taint_tracker
import agent_audit_ledger
import policy_envelope
from tests.phone_testing_keys import sign_enrollment_approval, get_test_pairing_code


class TestBatch30SecurityHardening(unittest.TestCase):

    def setUp(self):
        phone_approval_portal.clear_active_challenges()
        taint_tracker.clear_all_taints()
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)
        if os.path.exists(phone_approval_portal.DEVICE_REGISTRY_PATH):
            try: os.remove(phone_approval_portal.DEVICE_REGISTRY_PATH)
            except Exception: pass
        if os.path.exists(phone_approval_portal.CONSUMED_NONCES_PATH):
            try: os.remove(phone_approval_portal.CONSUMED_NONCES_PATH)
            except Exception: pass
        if os.path.exists(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH):
            try: os.remove(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH)
            except Exception: pass

    def tearDown(self):
        phone_approval_portal.clear_active_challenges()
        taint_tracker.clear_all_taints()
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)
        if os.path.exists(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH):
            try: os.remove(phone_approval_portal.ENROLLMENT_LOCKOUT_PATH)
            except Exception: pass

    def test_1_supervisor_fail_open_prevented_on_non_stepup_deny(self):
        """Vector 1: When action privilege check returns (False, False), proposal must DENY, never fall through."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        import heartbeat_lease
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        # Mock check_action_privilege returning hard DENY (not stepup)
        orig_check = taint_tracker.check_action_privilege
        taint_tracker.check_action_privilege = lambda c, t, tool, a: (False, False, "Hard policy deny: tainted workstation")
        try:
            payload = {
                "req_id": "req_deny_01",
                "tool": "homie_snap_window",
                "args": {"app_name": "notepad"},
            }
            reply_bytes = supervisor._handle_propose(payload, seq=1)
            _, _, _, reply, _ = homie_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
            self.assertEqual(reply["status"], "DENY", "Hard policy deny must return DENY, never fall through to mint!")
            self.assertEqual(reply["reason_code"], homie_supervisor.REASON_TAINTED_EXECUTION)
        finally:
            taint_tracker.check_action_privilege = orig_check
            supervisor.clean_shutdown()

    def test_2_supervisor_rejects_non_dict_arguments(self):
        """Vector 2: Supervisor must validate args is a dictionary up front, rejecting malformed types."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED

        for bad_args in ["string_payload", [1, 2, 3], None, 12345]:
            payload = {
                "req_id": "req_bad_args",
                "tool": "homie_snap_window",
                "args": bad_args
            }
            reply_bytes = supervisor._handle_propose(payload, seq=1)
            _, _, _, reply, _ = homie_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
            self.assertIn("error", reply)
            self.assertEqual(reply.get("reason_code"), homie_supervisor.REASON_MALFORMED_FRAME)

        supervisor.clean_shutdown()

    def test_3_supervisor_envelope_enforcement_in_handle_propose(self):
        """Vector 3: PolicyEnvelope domain scoping & image restrictions must be enforced inside _handle_propose."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        import heartbeat_lease
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        # Attach envelope scoping to example.com only
        envelope = policy_envelope.PolicyEnvelope(
            envelope_id="env_test_01",
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_launch_app"],
            step_budget=5,
            keystroke_cap=100,
            expiry=time.time() + 60.0,
            taint_epoch=taint_tracker.get_taint_epoch(),
            allowed_domains=["example.com"]
        )
        envelope.is_active = True
        supervisor.envelope = envelope

        # Propose navigating to evil.com
        payload = {
            "req_id": "req_env_01",
            "tool": "homie_launch_app",
            "args": {"target": "https://evil.com/phish", "domain": "evil.com"}
        }
        reply_bytes = supervisor._handle_propose(payload, seq=1)
        _, _, _, reply, _ = homie_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
        self.assertEqual(reply["status"], "DENY")
        self.assertIn("envelope", reply.get("reason", "").lower())

        supervisor.clean_shutdown()

    def test_4_supervisor_audit_outcome_written_in_finally(self):
        """Vector 4: Audit ledger OUTCOME entry must be recorded in a finally block even on tool execution exception."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        import heartbeat_lease
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        # Mock actuator to raise RuntimeError
        def mock_exec(*args, **kwargs):
            raise RuntimeError("Unexpected actuator crash!")
        orig_exec = supervisor.actuator.execute_actuator
        supervisor.actuator.execute_actuator = mock_exec

        try:
            payload = {
                "req_id": "req_crash_01",
                "tool": "homie_get_vitals",
                "args": {}
            }
            reply_bytes = supervisor._handle_propose(payload, seq=1)
            _, _, _, reply, _ = homie_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
            self.assertEqual(reply["status"], "DENY")
            self.assertIn("crash", reply.get("result", ""))

            # Verify audit ledger has OUTCOME entry for req_crash_01
            ledger_entries = agent_audit_ledger.query_audit_entries(limit=10)
            outcome_entries = [e for e in ledger_entries if "OUTCOME:req_crash_01" in e.get("decision", "")]
            self.assertTrue(len(outcome_entries) > 0, "OUTCOME ledger entry must be recorded even when execution throws!")
        finally:
            supervisor.actuator.execute_actuator = orig_exec
            supervisor.clean_shutdown()

    def test_5_enrollment_multi_sig_prevents_revoked_primary_bypass(self):
        """Vector 5: When primary_phone is revoked but device_b is active, enrolling device_c requires active device approval."""
        # Enroll primary_phone (Ed25519)
        from tests.phone_testing_keys import generate_test_phone_keypair, enroll_test_device
        priv_a, pub_a = enroll_test_device("primary_phone")

        # Enroll device_b with approval from primary_phone
        sess_b = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        code_b = get_test_pairing_code(sess_b)
        priv_b, pub_b = generate_test_phone_keypair()
        exp_b = int(time.time()) + 120
        sig_b = sign_enrollment_approval(priv_a, sess_b, "device_b", pub_b, expiry=exp_b)
        ok_b, _ = phone_approval_portal.complete_device_enrollment(sess_b, code_b, "device_b", pub_b, primary_approval_sig=sig_b, approval_expiry=exp_b)
        self.assertTrue(ok_b)

        # Revoke primary_phone
        phone_approval_portal.revoke_device_key("primary_phone")

        # Now attempt to enroll device_c without approval
        sess_c = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        code_c = get_test_pairing_code(sess_c)
        _, pub_c = generate_test_phone_keypair()

        # Enrolling without approval must FAIL because device_b is still active!
        ok_c, msg_c = phone_approval_portal.complete_device_enrollment(sess_c, code_c, "device_c", pub_c, primary_approval_sig=None)
        self.assertFalse(ok_c, "Enrollment must require active device approval even if primary is revoked!")
        self.assertIn("APPROVAL_REQUIRED", msg_c)

    def test_6_enrollment_multi_sig_binds_session_and_expiry(self):
        """Vector 6: Enrollment approval signature binds session_id and expiry (anti-replay across sessions)."""
        from tests.phone_testing_keys import enroll_test_device, generate_test_phone_keypair
        priv_a, _ = enroll_test_device("primary_phone")

        sess_1 = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        sess_2 = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        code_2 = get_test_pairing_code(sess_2)
        _, pub_b = generate_test_phone_keypair()

        # Signature minted for sess_1
        sig_sess_1 = sign_enrollment_approval(priv_a, sess_1, "device_b", pub_b, expiry=int(time.time())+120)

        # Attempting to use sig_sess_1 for sess_2 must be rejected
        ok, msg = phone_approval_portal.complete_device_enrollment(sess_2, code_2, "device_b", pub_b, primary_approval_sig=sig_sess_1)
        self.assertFalse(ok, "Replaying approval signature with mismatched session_id must fail!")
        self.assertIn("APPROVAL_INVALID", msg)

    def test_7_global_persistent_enrollment_lockout(self):
        """Vector 7: 5 failed pairing attempts across sessions triggers global persistent lockout."""
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)

        dummy_pem = "-----BEGIN PUBLIC KEY-----\n" + ("A" * 64) + "\n-----END PUBLIC KEY-----"
        for i in range(5):
            sess = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
            phone_approval_portal.complete_device_enrollment(sess, "000000_wrong", "dev_brute", dummy_pem)

        # 6th attempt should be locked out immediately
        sess_locked = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        self.assertEqual(sess_locked, "", "Global lockout must prevent creating new enrollment sessions!")

        # Unauthenticated reset must be denied
        res_unauth, _ = phone_approval_portal.reset_pairing_lockout(recovery_token=None)
        self.assertFalse(res_unauth)

        # Authenticated reset clears lockout
        tok2 = phone_approval_portal.generate_console_recovery_token()
        res_auth, _ = phone_approval_portal.reset_pairing_lockout(recovery_token=tok2)
        self.assertTrue(res_auth)

    def test_8_gateway_cors_and_dns_rebinding_protection(self):
        """Vector 8: Gateway rejects foreign Host and cross-origin Origin headers (no wildcard CORS)."""
        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self, headers):
                self.headers = headers
                self.sent_code = None
                self.sent_headers = {}
                self.sent_body = None
            def send_response(self, code):
                self.sent_code = code
            def send_header(self, k, v):
                self.sent_headers[k] = v
            def end_headers(self):
                pass
            def wfile_write(self, body):
                self.sent_body = body

        # 1. Foreign DNS rebinding Host header
        h1 = MockHandler({"Host": "attacker-dns-rebind.com", "Origin": "http://localhost:8080"})
        self.assertFalse(phone_gateway.is_request_host_allowed(h1.headers.get("Host")))

        # 2. Foreign cross-site Origin header
        h2 = MockHandler({"Host": "127.0.0.1:8080", "Origin": "https://evil-site.com"})
        self.assertFalse(phone_gateway.is_request_origin_allowed(h2.headers.get("Origin")))

        # 3. Legitimate local Host and Origin
        self.assertTrue(phone_gateway.is_request_host_allowed("127.0.0.1:8080"))
        self.assertTrue(phone_gateway.is_request_host_allowed("localhost:8080"))
        self.assertTrue(phone_gateway.is_request_origin_allowed("http://localhost:8080"))
        self.assertTrue(phone_gateway.is_request_origin_allowed(None))

    def test_9_gateway_deny_challenge_endpoint(self):
        """Vector 9: POST /api/deny-challenge actively purges the challenge from the server."""
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_deny_001",
            tool_name="homie_snap_window",
            arguments={},
            session_id="sess_deny",
            taint_epoch=0,
            device_id="primary_phone"
        )
        self.assertIn("step_deny_001", phone_approval_portal._ACTIVE_CHALLENGES)

        # Deny the challenge via portal
        ok, msg = phone_approval_portal.deny_approval_challenge("step_deny_001", device_id="primary_phone")
        self.assertTrue(ok)
        self.assertNotIn("step_deny_001", phone_approval_portal._ACTIVE_CHALLENGES)

    def test_10_ecdsa_p256_and_ed25519_asymmetric_support(self):
        """Vector 10: Supports WebCrypto standard ECDSA P-256 signatures alongside Ed25519."""
        # Generate P-256 keypair
        p256_key = ECC.generate(curve='P-256')
        p256_pub_pem = p256_key.public_key().export_key(format='PEM')

        # Test message and signature
        message = b"CANONICAL_CHALLENGE_BYTES_P256"
        h = SHA256.new(message)
        signer = DSS.new(p256_key, 'fips-186-3')
        sig_bytes = signer.sign(h)
        sig_hex = sig_bytes.hex()

        # Verification through phone_approval_portal
        verified = phone_approval_portal.verify_asymmetric_signature(p256_pub_pem, message, sig_hex)
        self.assertTrue(verified, "ECDSA P-256 signature from standard WebCrypto curve must verify!")

        # Tampered message must fail
        tampered = phone_approval_portal.verify_asymmetric_signature(p256_pub_pem, b"TAMPERED_BYTES", sig_hex)
        self.assertFalse(tampered)


if __name__ == "__main__":
    unittest.main()
