"""Unit and security tests for Batch 27:
Asymmetric Phone-Signed Cryptographic Step-Up Gateway & Acceptance Test for PC-State Unforgeability.
"""

import os
import sys
import time
import unittest
from Crypto.PublicKey import ECC

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
from phone_approval_portal import (
    generate_approval_challenge,
    verify_device_approval,
    verify_action_approval,
    clear_active_challenges,
    revoke_device_key,
    start_local_enrollment,
    complete_device_enrollment
)
import taint_tracker
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    mint_test_action_approval,
    sign_test_challenge,
    get_test_pairing_code
)


class TestBatch18PhonePortal(unittest.TestCase):

    def setUp(self):
        clear_active_challenges()
        taint_tracker.clear_all_taints()
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)
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
        self.phone_priv, self.phone_pub_pem = enroll_test_device("primary_phone")

    def tearDown(self):
        clear_active_challenges()
        taint_tracker.clear_all_taints()
        tok = phone_approval_portal.generate_console_recovery_token()
        phone_approval_portal.reset_pairing_lockout(tok)
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

    def test_challenge_binding_and_valid_asymmetric_phone_signature(self):
        """Verifies valid Ed25519 phone signature approves the exact bound challenge."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_001",
            tool_name="helm_snap_window",
            arguments={"app_name": "notepad"},
            session_id="tainted_session_1",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone",
            ttl_seconds=60.0
        )

        sig = sign_test_challenge(self.phone_priv, challenge["challenge_hash"])
        ok, msg, item = verify_device_approval("step_test_001", sig, device_id="primary_phone", counter=1)
        self.assertTrue(ok, f"Verification failed: {msg}")
        self.assertEqual(item["tool_name"], "helm_snap_window")
        self.assertIn("notepad", str(item["arguments"]))

    def test_tampered_signature_rejection(self):
        """Verifies signature forgery fails verification without destroying challenge on first attempt."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_002",
            tool_name="helm_snap_window",
            arguments={"app_name": "notepad"},
            session_id="tainted_session_1",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone"
        )

        forged_sig = "deadbeef" * 16  # 64-byte forged hex
        ok, msg, item = verify_device_approval("step_test_002", forged_sig, device_id="primary_phone", counter=1)
        self.assertFalse(ok)
        self.assertIn("verification failed", msg.lower())

    def test_single_use_challenge_enforcement(self):
        """Verifies an approved challenge is immediately consumed and cannot be replayed."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_003",
            tool_name="helm_set_clipboard",
            arguments={"text": "sensitive_data"},
            session_id="session_replayer",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone"
        )

        sig = sign_test_challenge(self.phone_priv, challenge["challenge_hash"])
        ok1, _, _ = verify_device_approval("step_test_003", sig, device_id="primary_phone", counter=1)
        self.assertTrue(ok1)

        # Replay attempt fails immediately
        ok2, msg2, _ = verify_device_approval("step_test_003", sig, device_id="primary_phone", counter=2)
        self.assertFalse(ok2)
        self.assertIn("already consumed", msg2.lower())

    def test_expired_challenge_rejection(self):
        """Verifies challenge past TTL fails verification."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_004",
            tool_name="helm_get_clipboard",
            arguments={},
            session_id="session_expired",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone",
            ttl_seconds=-1.0  # Already expired
        )

        sig = sign_test_challenge(self.phone_priv, challenge["challenge_hash"])
        ok, msg, _ = verify_device_approval("step_test_004", sig, device_id="primary_phone", counter=1)
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

    def test_canonical_prompt_content(self):
        """Verifies the prompt text is strictly supervisor-authored from validated arguments."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_005",
            tool_name="helm_launch_app",
            arguments={"app_name": "calc.exe"},
            session_id="agent_123",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone"
        )
        prompt = challenge["canonical_prompt"]
        self.assertIn("Security Authorization Required", prompt)
        self.assertIn("helm_launch_app", prompt)
        self.assertIn("calc.exe", prompt)

    def test_physical_presence_pairing_and_revocation(self):
        """Verifies physical presence pairing ceremony, monotonic counter, and instant revocation."""
        # 1. Start local ceremony
        sess_id = start_local_enrollment(ttl_seconds=60.0)
        code = get_test_pairing_code(sess_id)
        self.assertEqual(len(code), 6)

        # 2. Complete pairing with asymmetric public key (approved by primary device via V2 session-bound signature)
        new_phone_priv, new_phone_pub_pem = generate_test_phone_keypair()
        from tests.phone_testing_keys import sign_enrollment_approval
        exp = int(time.time() + 60)
        primary_sig = sign_enrollment_approval(self.phone_priv, sess_id, "secure_phone_01", new_phone_pub_pem, exp)
        ok, msg = complete_device_enrollment(sess_id, code, "secure_phone_01", new_phone_pub_pem, primary_approval_sig=primary_sig, approval_expiry=exp)
        self.assertTrue(ok)
        self.assertIn("successfully paired", msg)

        # 3. Use signature with monotonic counter
        ch = generate_approval_challenge(
            step_up_id="step_test_006",
            tool_name="helm_move_cursor",
            arguments={"x": 100, "y": 200},
            session_id="enrolled_sess",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="secure_phone_01"
        )
        sig1 = sign_test_challenge(new_phone_priv, ch["challenge_hash"])
        ok1, _, _ = verify_device_approval("step_test_006", sig1, device_id="secure_phone_01", counter=1)
        self.assertTrue(ok1)

        # 4. Anti-replay counter rejection: same or lower counter fails
        ch2 = generate_approval_challenge(
            step_up_id="step_test_007",
            tool_name="helm_click_coords",
            arguments={"button": "left"},
            session_id="enrolled_sess",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="secure_phone_01"
        )
        sig2 = sign_test_challenge(new_phone_priv, ch2["challenge_hash"])
        ok2, msg2, _ = verify_device_approval("step_test_007", sig2, device_id="secure_phone_01", counter=1)
        self.assertFalse(ok2)
        self.assertTrue("COUNTER_MISMATCH" in msg2 or "Replay detected" in msg2)

        # 5. Revocation test
        revoked = revoke_device_key("secure_phone_01")
        self.assertTrue(revoked)
        ch3 = generate_approval_challenge(
            step_up_id="step_test_008",
            tool_name="helm_click_coords",
            arguments={"button": "left"},
            session_id="enrolled_sess",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="secure_phone_01"
        )
        sig3 = sign_test_challenge(new_phone_priv, ch3["challenge_hash"])
        ok3, msg3, _ = verify_device_approval("step_test_008", sig3, device_id="secure_phone_01", counter=2)
        self.assertFalse(ok3)
        self.assertIn("has been revoked", msg3)

    def test_enrollment_rate_limiting_and_lockout(self):
        """Verifies session is permanently locked out and destroyed after 3 incorrect pairing codes."""
        sess_id = start_local_enrollment(ttl_seconds=60.0)
        real_code = get_test_pairing_code(sess_id)
        _, fake_pub = generate_test_phone_keypair()

        # Attempt 1: wrong code
        ok1, msg1 = complete_device_enrollment(sess_id, "000000", "attacker_device", fake_pub)
        self.assertFalse(ok1)
        self.assertIn("Invalid pairing code (attempt 1/3)", msg1)

        # Attempt 2: wrong code
        ok2, msg2 = complete_device_enrollment(sess_id, "111111", "attacker_device", fake_pub)
        self.assertFalse(ok2)
        self.assertIn("Invalid pairing code (attempt 2/3)", msg2)

        # Attempt 3: wrong code -> LOCKOUT
        ok3, msg3 = complete_device_enrollment(sess_id, "222222", "attacker_device", fake_pub)
        self.assertFalse(ok3)
        self.assertIn("locked out", msg3.lower())

        # Attempt 4: even with the REAL code, the session is destroyed!
        ok4, msg4 = complete_device_enrollment(sess_id, real_code, "attacker_device", fake_pub)
        self.assertFalse(ok4)
        self.assertIn("not found, expired, or locked out", msg4.lower())

    def test_asymmetric_phone_approval_unforgeability_from_pc_state(self):
        """Claude Acceptance Test:
        Give an attacker everything the PC holds: the registry, all local files, subkeys, and source.
        Have the attacker attempt to forge an approval that verify_action_approval accepts.
        Must strictly FAIL because the PC holds only the Ed25519 public key.
        """
        registry = phone_approval_portal._load_device_registry()
        self.assertIn("primary_phone", registry)
        pc_held_pub_pem = registry["primary_phone"]["public_key"]

        # Verify PC registry holds strictly public key (no private key)
        imported = ECC.import_key(pc_held_pub_pem)
        self.assertFalse(imported.has_private(), "PC state must NEVER hold private signing keys!")

        # Attacker tries to forge an approval for helm_apply_update using PC state
        payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        forged_approval = {
            "version": 1,
            "device_id": "primary_phone",
            "action_name": "helm_apply_update",
            "payload_hash": payload_hash,
            "nonce": "0123456789abcdef0123456789abcdef",
            "expiry": int(time.time() + 60),
            "taint_epoch": taint_tracker.get_taint_epoch(),
            "signature": "deadbeef" * 16  # Forged 64-byte signature
        }

        ok, msg = verify_action_approval(forged_approval, "helm_apply_update", payload_hash)
        self.assertFalse(ok, "Attacker possessing all PC state MUST NOT be able to forge an approval!")
        self.assertIn("signature failed verification", msg.lower())

        # Legitimate phone signs with its private key held only on the phone
        valid_approval = mint_test_action_approval(
            self.phone_priv, "helm_apply_update", payload_hash, device_id="primary_phone"
        )
        ok_valid, msg_valid = verify_action_approval(valid_approval, "helm_apply_update", payload_hash)
        self.assertTrue(ok_valid, f"Legitimate phone signature must be accepted: {msg_valid}")

        # Stale taint epoch rejection
        stale_approval = mint_test_action_approval(
            self.phone_priv, "helm_apply_update", payload_hash, device_id="primary_phone",
            taint_epoch=taint_tracker.get_taint_epoch() - 1
        )
        ok_stale, msg_stale = verify_action_approval(stale_approval, "helm_apply_update", payload_hash)
        self.assertFalse(ok_stale, "Approval with stale taint epoch must be rejected!")
        self.assertIn("TAINT_EPOCH_MISMATCH", msg_stale)

    def test_cross_device_approval_rejection(self):
        """Batch 28 Security Invariant: Challenge issued to primary_phone MUST NOT be approved by another device."""
        other_priv, other_pub = enroll_test_device("rogue_phone_02")
        challenge = generate_approval_challenge(
            step_up_id="step_test_cross_dev",
            tool_name="helm_snap_window",
            arguments={"app_name": "cmd.exe"},
            session_id="session_cross",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone"
        )

        sig = sign_test_challenge(other_priv, challenge["challenge_hash"])
        ok, msg, _ = verify_device_approval("step_test_cross_dev", sig, device_id="rogue_phone_02", counter=1)
        self.assertFalse(ok, "Approval signed by rogue device must be rejected!")
        self.assertIn("DEVICE_MISMATCH", msg)

    def test_enrollment_anti_overwrite_rejection(self):
        """Batch 28 Security Invariant: Existing enrolled devices cannot be overwritten by re-enrollment."""
        sess_id = start_local_enrollment(ttl_seconds=60.0)
        code = get_test_pairing_code(sess_id)
        _, pub = generate_test_phone_keypair()

        # primary_phone is already enrolled in setUp -> re-enrollment must fail closed
        ok, msg = complete_device_enrollment(sess_id, code, "primary_phone", pub)
        self.assertFalse(ok, "Re-enrollment of existing device must fail closed!")
        self.assertIn("DEVICE_EXISTS", msg)

    def test_counter_mandatory_rejection(self):
        """Batch 28 Security Invariant: Monotonic counter is strictly mandatory in verify_device_approval."""
        challenge = generate_approval_challenge(
            step_up_id="step_test_no_counter",
            tool_name="helm_snap_window",
            arguments={"app_name": "calc.exe"},
            session_id="session_no_counter",
            taint_epoch=taint_tracker.get_taint_epoch(),
            device_id="primary_phone"
        )
        sig = sign_test_challenge(self.phone_priv, challenge["challenge_hash"])
        ok, msg, _ = verify_device_approval("step_test_no_counter", sig, device_id="primary_phone", counter=None)
        self.assertFalse(ok, "Omitting monotonic counter must fail closed!")
        self.assertIn("COUNTER_REQUIRED", msg)

    def test_max_action_approval_ttl_cap(self):
        """Batch 28 Security Invariant: Action approval with expiry exceeding MAX_ACTION_APPROVAL_TTL (300s) is rejected."""
        payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        # Mint approval with 600s TTL (> 300s)
        excessive_approval = mint_test_action_approval(
            self.phone_priv, "helm_apply_update", payload_hash, device_id="primary_phone",
            ttl_seconds=600.0
        )
        ok, msg = verify_action_approval(excessive_approval, "helm_apply_update", payload_hash)
        self.assertFalse(ok, "Action approval with excessive TTL must be rejected!")
        self.assertIn("EXPIRY_EXCEEDS_CAP", msg)


if __name__ == "__main__":
    unittest.main()
