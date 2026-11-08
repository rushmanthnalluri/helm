"""Unit and security tests for Batch 18B:
Phone-Signed Cryptographic Step-Up Gateway.
"""

import os
import sys
import time
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
from phone_approval_portal import (
    generate_approval_challenge, compute_device_signature,
    verify_device_approval, clear_active_challenges,
    get_or_create_device_public_key
)
import taint_tracker


class TestBatch18PhonePortal(unittest.TestCase):

    def setUp(self):
        clear_active_challenges()
        taint_tracker.clear_all_taints()

    def tearDown(self):
        clear_active_challenges()
        taint_tracker.clear_all_taints()

    def test_challenge_binding_and_valid_phone_signature(self):
        """Verifies valid phone device signature approves the exact bound challenge."""
        device_key = "device_secret_phone_key_9999"
        challenge = generate_approval_challenge(
            step_up_id="step_test_001",
            tool_name="homie_snap_window",
            arguments={"app_name": "notepad"},
            session_id="tainted_session_1",
            taint_epoch=1700000000,
            ttl_seconds=60.0
        )

        # Phone signs the challenge hash using its hardware device key
        sig = compute_device_signature(challenge["challenge_hash"], device_key)

        ok, msg, item = verify_device_approval(
            "step_test_001", sig, device_key_override=device_key
        )
        self.assertTrue(ok, f"Verification failed: {msg}")
        self.assertEqual(item["tool_name"], "homie_snap_window")
        self.assertIn("notepad", str(item["arguments"]))

    def test_tampered_signature_rejection(self):
        """Verifies signature forgery or altered device key fails verification."""
        device_key = "device_secret_phone_key_9999"
        challenge = generate_approval_challenge(
            step_up_id="step_test_002",
            tool_name="homie_snap_window",
            arguments={"app_name": "notepad"},
            session_id="tainted_session_1",
            taint_epoch=1700000000
        )

        forged_sig = "deadbeef" * 8
        ok, msg, item = verify_device_approval(
            "step_test_002", forged_sig, device_key_override=device_key
        )
        self.assertFalse(ok)
        self.assertIn("forgery/tampering rejected", msg)

    def test_single_use_challenge_enforcement(self):
        """Verifies an approved challenge is immediately consumed and cannot be replayed."""
        device_key = "device_secret_phone_key_9999"
        challenge = generate_approval_challenge(
            step_up_id="step_test_003",
            tool_name="homie_set_clipboard",
            arguments={"text": "sensitive_data"},
            session_id="session_replayer",
            taint_epoch=1700000000
        )

        sig = compute_device_signature(challenge["challenge_hash"], device_key)
        ok1, _, _ = verify_device_approval("step_test_003", sig, device_key_override=device_key)
        self.assertTrue(ok1)

        # Replay attempt
        ok2, msg2, _ = verify_device_approval("step_test_003", sig, device_key_override=device_key)
        self.assertFalse(ok2)
        self.assertIn("already consumed", msg2)

    def test_expired_challenge_rejection(self):
        """Verifies challenge past TTL fails verification."""
        device_key = "device_secret_phone_key_9999"
        challenge = generate_approval_challenge(
            step_up_id="step_test_004",
            tool_name="homie_get_clipboard",
            arguments={},
            session_id="session_expired",
            taint_epoch=1700000000,
            ttl_seconds=-1.0  # Already expired
        )

        sig = compute_device_signature(challenge["challenge_hash"], device_key)
        ok, msg, _ = verify_device_approval("step_test_004", sig, device_key_override=device_key)
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

    def test_canonical_prompt_content(self):
        """Verifies the prompt text is strictly supervisor-authored from validated arguments."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_005",
            tool_name="homie_launch_app",
            arguments={"app_name": "calc.exe"},
            session_id="agent_123",
            taint_epoch=1700000000
        )
        prompt = challenge["canonical_prompt"]
        self.assertIn("Security Authorization Required", prompt)
        self.assertIn("homie_launch_app", prompt)
        self.assertIn("calc.exe", prompt)

    def test_physical_presence_pairing_and_revocation(self):
        """Verifies physical presence pairing ceremony, monotonic counter, and instant revocation."""
        from phone_approval_portal import (
            start_local_enrollment, complete_device_enrollment, revoke_device_key
        )
        # 1. Start local ceremony
        sess_id, code = start_local_enrollment(ttl_seconds=60.0)
        self.assertEqual(len(code), 6)

        # 2. Complete pairing
        phone_key = "secure_enclave_key_7777"
        ok, msg = complete_device_enrollment(sess_id, code, "secure_phone_01", phone_key)
        self.assertTrue(ok)
        self.assertIn("successfully paired", msg)

        # 3. Use signature with counter
        ch = generate_approval_challenge(
            step_up_id="step_test_006",
            tool_name="homie_move_cursor",
            arguments={"x": 100, "y": 200},
            session_id="enrolled_sess",
            taint_epoch=1700000000,
            device_id="secure_phone_01"
        )
        sig1 = compute_device_signature(ch["challenge_hash"], phone_key)
        ok1, _, _ = verify_device_approval("step_test_006", sig1, device_id="secure_phone_01", counter=1)
        self.assertTrue(ok1)

        # 4. Anti-replay counter rejection: same or lower counter fails
        ch2 = generate_approval_challenge(
            step_up_id="step_test_007",
            tool_name="homie_click_coords",
            arguments={"button": "left"},
            session_id="enrolled_sess",
            taint_epoch=1700000000,
            device_id="secure_phone_01"
        )
        sig2 = compute_device_signature(ch2["challenge_hash"], phone_key)
        ok2, msg2, _ = verify_device_approval("step_test_007", sig2, device_id="secure_phone_01", counter=1)
        self.assertFalse(ok2)
        self.assertIn("Replay detected", msg2)

        # 5. Revocation test
        revoked = revoke_device_key("secure_phone_01")
        self.assertTrue(revoked)
        ch3 = generate_approval_challenge(
            step_up_id="step_test_008",
            tool_name="homie_click_coords",
            arguments={"button": "left"},
            session_id="enrolled_sess",
            taint_epoch=1700000000,
            device_id="secure_phone_01"
        )
        sig3 = compute_device_signature(ch3["challenge_hash"], phone_key)
        ok3, msg3, _ = verify_device_approval("step_test_008", sig3, device_id="secure_phone_01", counter=2)
        self.assertFalse(ok3)
        self.assertIn("has been revoked", msg3)


    def test_enrollment_rate_limiting_and_lockout(self):
        """Verifies session is permanently locked out and destroyed after 3 incorrect pairing codes."""
        from phone_approval_portal import start_local_enrollment, complete_device_enrollment
        sess_id, real_code = start_local_enrollment(ttl_seconds=60.0)

        # Attempt 1: wrong code
        ok1, msg1 = complete_device_enrollment(sess_id, "000000", "attacker_device", "key1")
        self.assertFalse(ok1)
        self.assertIn("Invalid pairing code (attempt 1/3)", msg1)

        # Attempt 2: wrong code
        ok2, msg2 = complete_device_enrollment(sess_id, "111111", "attacker_device", "key1")
        self.assertFalse(ok2)
        self.assertIn("Invalid pairing code (attempt 2/3)", msg2)

        # Attempt 3: wrong code -> LOCKOUT
        ok3, msg3 = complete_device_enrollment(sess_id, "222222", "attacker_device", "key1")
        self.assertFalse(ok3)
        self.assertIn("locked out", msg3.lower())

        # Attempt 4: even with the REAL code, the session is destroyed!
        ok4, msg4 = complete_device_enrollment(sess_id, real_code, "attacker_device", "key1")
        self.assertFalse(ok4)
        self.assertIn("not found, expired, or locked out", msg4.lower())


if __name__ == "__main__":
    unittest.main()
