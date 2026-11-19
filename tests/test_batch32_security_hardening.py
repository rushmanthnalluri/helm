"""Unit tests for Batch 32 security hardening and verification directives:
1. Complete elimination of is_console_presence boolean in reset_pairing_lockout.
2. Revoked-primary recovery fails closed (requires console recovery token).
3. Complete elimination of V1 enrollment replay fallback and strict signed expiry in V2.
4. Elimination of get_session_pairing_code_for_testing from production code.
5. Production caller for start_local_enrollment via try_fast_command and app API.
6. Policy Envelope fail-closed omission defenses (missing process, missing domain, case-insensitive Enter).
7. Atomic policy envelope step reservation and release.
8. Supervisor client token enforcement fails closed when token is omitted.
9. Supervisor locks down immediately if INTENT audit ledger write fails.
10. Supervisor internal approval cache binds caller_id with TTL.
"""
import os
import sys
import time
import json
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import policy_envelope
import helm_supervisor
import client_token_auth
import agent_audit_ledger
import taint_tracker
import kill_switch
import helm

# Testing helper for Ed25519 signatures
from Crypto.Signature import eddsa
from tests.phone_testing_keys import generate_test_phone_keypair, sign_enrollment_approval


class TestBatch32SecurityHardening(unittest.TestCase):
    def setUp(self):
        os.environ["HELM_TEST_ENV"] = "1"
        os.environ["HELM_COMPLETE_MEDIATION"] = "1"
        # Reset lockout and dirty flags
        for f in [".helm_supervisor_dirty.flag", ".helm_enrollment_lockout.json"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        # Reset phone approval portal state
        with phone_approval_portal._ENROLLMENT_LOCK:
            phone_approval_portal._LOCAL_ENROLLMENT_SESSIONS.clear()
            phone_approval_portal._CONSOLE_RECOVERY_TOKENS.clear()
        phone_approval_portal._ACTIVE_CHALLENGES.clear()
        # Reset display driver
        phone_approval_portal.set_display_driver(None)

    def tearDown(self):
        phone_approval_portal.set_display_driver(None)
        client_token_auth.set_token_enforcement(False)

    def test_1_reset_pairing_lockout_rejects_boolean_requires_token(self):
        """Directive 1: reset_pairing_lockout must NOT accept boolean presence; requires valid recovery token."""
        # Record 5 failed attempts to trigger lockout
        for _ in range(5):
            phone_approval_portal.record_failed_enrollment_attempt()
        self.assertTrue(phone_approval_portal.is_enrollment_locked_out())

        # Calling without a recovery token must fail closed
        ok, msg = phone_approval_portal.reset_pairing_lockout()
        self.assertFalse(ok)
        self.assertIn("token", msg.lower())
        self.assertTrue(phone_approval_portal.is_enrollment_locked_out())

        # Generating a valid single-use console recovery token must successfully reset
        tok = phone_approval_portal.generate_console_recovery_token()
        ok2, msg2 = phone_approval_portal.reset_pairing_lockout(recovery_token=tok)
        self.assertTrue(ok2)
        self.assertFalse(phone_approval_portal.is_enrollment_locked_out())

        # Re-using the same token must fail (single-use)
        ok3, msg3 = phone_approval_portal.reset_pairing_lockout(recovery_token=tok)
        self.assertFalse(ok3)

    def test_2_revoked_primary_recovery_fails_closed_without_token(self):
        """Directive 2: If all registered devices are revoked, new enrollment must fail closed unless recovery token is provided."""
        # Setup registry where all devices are revoked
        priv_key_ecc, pub_key_pem = generate_test_phone_keypair()
        with phone_approval_portal._REGISTRY_LOCK:
            phone_approval_portal._save_device_registry({
                "lost_phone": {
                    "public_key": pub_key_pem,
                    "authenticator_type": "device_resident_ed25519",
                    "paired_at": time.time(),
                    "counter": 5,
                    "revoked": True,
                    "device_name": "Lost Phone"
                }
            })

        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        self.assertTrue(len(captured) > 0)
        code = captured[0]

        new_priv, new_pub = generate_test_phone_keypair()

        # Enrolling without recovery token must FAIL CLOSED
        ok, msg = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "new_phone", new_pub
        )
        self.assertFalse(ok)
        self.assertIn("revoked", msg.lower())

        # Start a new session and enroll WITH a valid recovery token -> succeeds
        captured.clear()
        sess_id2 = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code2 = captured[0]

        rec_tok = phone_approval_portal.generate_console_recovery_token()
        ok2, msg2 = phone_approval_portal.complete_device_enrollment(
            sess_id2, code2, "new_phone", new_pub, recovery_token=rec_tok
        )
        self.assertTrue(ok2)

    def test_3_v1_fallback_eliminated_and_v2_strictly_verifies_signed_expiry(self):
        """Directive 3: V1 fallback is rejected; V2 requires explicit valid signed expiry."""
        priv1, pub1 = generate_test_phone_keypair()
        with phone_approval_portal._REGISTRY_LOCK:
            phone_approval_portal._save_device_registry({
                "primary_phone": {
                    "public_key": pub1,
                    "authenticator_type": "device_resident_ed25519",
                    "paired_at": time.time(),
                    "counter": 0,
                    "revoked": False,
                    "device_name": "Primary Device"
                }
            })

        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code = captured[0]

        priv2, pub2 = generate_test_phone_keypair()

        # Attempt V1 signature (ENROLL_DEVICE_V1) -> MUST FAIL (V1 removed)
        v1_msg = f"ENROLL_DEVICE_V1|second_phone|{pub2.strip()}".encode('utf-8')
        v1_sig = eddsa.new(priv1, 'rfc8032').sign(v1_msg).hex()

        ok_v1, msg_v1 = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "second_phone", pub2, primary_approval_sig=v1_sig
        )
        self.assertFalse(ok_v1)
        self.assertIn("invalid", msg_v1.lower())

        # Attempt V2 signature with expired expiry -> MUST FAIL
        captured.clear()
        sess_id2 = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code2 = captured[0]

        past_expiry = int(time.time() - 10)
        v2_past_sig = sign_enrollment_approval(priv1, sess_id2, "second_phone", pub2, past_expiry)

        ok_past, msg_past = phone_approval_portal.complete_device_enrollment(
            sess_id2, code2, "second_phone", pub2, primary_approval_sig=v2_past_sig, approval_expiry=past_expiry
        )
        self.assertFalse(ok_past)
        self.assertIn("expired", msg_past.lower())

        valid_expiry = int(time.time() + 120)

        # Attempt V2 signature with tampered/forged signature -> MUST FAIL
        captured.clear()
        sess_id4 = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code4 = captured[0]
        ok_forged, msg_forged = phone_approval_portal.complete_device_enrollment(
            sess_id4, code4, "second_phone", pub2, primary_approval_sig="aa" * 64, approval_expiry=valid_expiry
        )
        self.assertFalse(ok_forged)
        self.assertIn("invalid", msg_forged.lower())

        # Valid V2 signature with unexpired expiry (within 300s cap) -> SUCCEEDS
        captured.clear()
        sess_id3 = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code3 = captured[0]

        v2_valid_sig = sign_enrollment_approval(priv1, sess_id3, "second_phone", pub2, valid_expiry)

        ok_v2, msg_v2 = phone_approval_portal.complete_device_enrollment(
            sess_id3, code3, "second_phone", pub2, primary_approval_sig=v2_valid_sig, approval_expiry=valid_expiry
        )
        self.assertTrue(ok_v2)

    def test_4_no_get_session_pairing_code_for_testing_in_production(self):
        """Directive 4: phone_approval_portal must NOT expose get_session_pairing_code_for_testing in production."""
        self.assertFalse(hasattr(phone_approval_portal, "get_session_pairing_code_for_testing"),
                         "Production module phone_approval_portal must not contain get_session_pairing_code_for_testing helper")

    def test_5_fast_command_pair_phone_disabled_against_acoustic_injection(self):
        """Directive 5 (Refined in Batch 33): Fast command 'pair phone' must NOT trigger enrollment due to acoustic injection risk."""
        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)

        handled, msg = helm.try_fast_command("pair phone")
        self.assertFalse(handled, "Acoustic injection prevention: 'pair phone' must not be triggered via ambient voice")
        self.assertEqual(len(captured), 0)

    def test_6_policy_envelope_fail_closed_omissions(self):
        """Directive 6: Policy envelope check_boundary fails closed on missing process, missing domain, or Enter."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["helm_agent_type", "helm_browse"],
            step_budget=5,
            keystroke_cap=100,
            allowed_domains=["secure-portal.com"],
            taint_epoch=1
        )
        env.is_active = True

        # Case A: Missing process image when allowed_process_images is specified -> MUST DENY
        ok_a, msg_a, _ = env.check_boundary("helm_agent_type", {"text": "hello"}, current_process_image=None, current_taint_epoch=1, current_domain="secure-portal.com")
        self.assertFalse(ok_a)
        self.assertIn("process", msg_a.lower())

        # Case B: Missing domain for browser action when allowed_domains is specified -> MUST DENY
        ok_b, msg_b, _ = env.check_boundary("helm_browse", {"url": "https://secure-portal.com"}, current_process_image="chrome.exe", current_taint_epoch=1, current_domain=None)
        self.assertFalse(ok_b)
        self.assertIn("domain", msg_b.lower())

        # Case C: Key is "Enter" or "ENTER" with capital letters -> MUST DENY
        ok_c, msg_c, _ = env.check_boundary("helm_agent_type", {"key": "Enter"}, current_process_image="chrome.exe", current_taint_epoch=1, current_domain="secure-portal.com")
        self.assertFalse(ok_c)
        self.assertIn("enter", msg_c.lower())

        ok_d, msg_d, _ = env.check_boundary("helm_agent_type", {"key": "ENTER"}, current_process_image="chrome.exe", current_taint_epoch=1, current_domain="secure-portal.com")
        self.assertFalse(ok_d)
        self.assertIn("enter", msg_d.lower())

    def test_7_atomic_step_reservation_and_release(self):
        """Directive 7: check_boundary reserves a step, and release_reservation frees it on failure."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["helm_agent_type"],
            step_budget=1,
            keystroke_cap=100,
            allowed_domains=["secure-portal.com"],
            taint_epoch=1
        )
        env.is_active = True

        # First check reserves the single available step
        ok1, msg1, ks1 = env.check_boundary("helm_agent_type", {"text": "a"}, "chrome.exe", 1, "secure-portal.com")
        self.assertTrue(ok1)

        # Immediate second concurrent check exceeds budget due to reservation!
        ok2, msg2, ks2 = env.check_boundary("helm_agent_type", {"text": "b"}, "chrome.exe", 1, "secure-portal.com")
        self.assertFalse(ok2)
        self.assertIn("budget", msg2.lower())

        # Releasing reservation allows subsequent check to pass
        env.release_reservation()
        ok3, msg3, ks3 = env.check_boundary("helm_agent_type", {"text": "c"}, "chrome.exe", 1, "secure-portal.com")
        self.assertTrue(ok3)

        # Committing step permanently records it
        env.commit_step(ks3)
        self.assertEqual(env.steps_consumed, 1)

    def test_8_supervisor_client_token_enforcement_fails_closed(self):
        """Directive 8: When client token enforcement is active, omitting client_token fails closed."""
        import heartbeat_lease
        client_token_auth.set_token_enforcement(True)
        supervisor = helm_supervisor.PolicySupervisor()
        supervisor.state = helm_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=30.0)
        supervisor.last_heartbeat_time = time.time()

        # Omitting client_token must be DENIED
        reply_bytes = supervisor._handle_propose({
            "tool": "helm_get_vitals",
            "args": {},
            "client_token": None
        }, seq=1)
        _, _, _, payload, _ = helm_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
        self.assertEqual(payload.get("status"), "DENY")
        self.assertEqual(payload.get("reason_code"), helm_supervisor.REASON_UNAUTHORIZED_TOKEN)

    def test_9_supervisor_locks_if_intent_ledger_fails(self):
        """Directive 9: If audit ledger write for INTENT fails, supervisor must transition to LOCKED."""
        import heartbeat_lease
        supervisor = helm_supervisor.PolicySupervisor()
        supervisor.state = helm_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=30.0)
        supervisor.last_heartbeat_time = time.time()

        with patch("agent_audit_ledger.record_agent_action", side_effect=IOError("Disk write failure")):
            reply_bytes = supervisor._handle_propose({
                "tool": "helm_set_clipboard",
                "args": {"text": "test"}
            }, seq=1)

            self.assertEqual(supervisor.state, helm_supervisor.STATE_LOCKED)
            _, msg_type, _, payload, _ = helm_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
            self.assertEqual(msg_type, helm_supervisor.MSG_ERROR)

    def test_10_approval_cache_binds_caller_id_with_ttl(self):
        """Directive 10: Supervisor approval cache strictly binds (caller_id, tool, args_hash, taint_epoch)."""
        supervisor = helm_supervisor.PolicySupervisor()
        args_hash = "abc123hash"
        from tests.phone_testing_keys import enroll_test_device, mint_test_action_approval
        priv_k, pub_k = enroll_test_device("primary_phone")
        signed_blob = mint_test_action_approval(priv_k, "helm_set_clipboard", args_hash, "primary_phone", taint_epoch=2)
        signed_blob["caller_id"] = "worker_1"
        signed_blob["tool_name"] = "helm_set_clipboard"
        signed_blob["args_hash"] = args_hash
        supervisor.record_approved_action("worker_1", "helm_set_clipboard", args_hash, taint_epoch=2, ttl=60.0, signed_blob=signed_blob)

        # Wrong caller cannot consume and must not evict legitimate approval from cache
        consumed_wrong_caller = supervisor.consume_approved_action("worker_2", "helm_set_clipboard", args_hash, taint_epoch=2)
        self.assertFalse(consumed_wrong_caller)
        self.assertIn(("worker_1", "helm_set_clipboard", args_hash.lower(), 2), supervisor._approved_actions, "Wrong caller evicted legitimate approval from cache!")

        # Wrong taint epoch cannot consume
        consumed_wrong_epoch = supervisor.consume_approved_action("worker_1", "helm_set_clipboard", args_hash, taint_epoch=3)
        self.assertFalse(consumed_wrong_epoch)

        # Correct caller and epoch consumes successfully
        consumed_ok = supervisor.consume_approved_action("worker_1", "helm_set_clipboard", args_hash, taint_epoch=2)
        self.assertTrue(consumed_ok)

        # Single-use: cannot consume twice
        consumed_again = supervisor.consume_approved_action("worker_1", "helm_set_clipboard", args_hash, taint_epoch=2)
        self.assertFalse(consumed_again)


if __name__ == "__main__":
    unittest.main()
