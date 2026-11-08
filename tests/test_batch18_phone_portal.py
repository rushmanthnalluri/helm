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


if __name__ == "__main__":
    unittest.main()
