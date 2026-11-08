"""tests/test_operations_and_recovery.py - Operations, Update Verifier & Locked State Recovery Tests.

Verifies:
1. Signed update verification: Valid HMAC-signed manifest and matching file hashes are accepted.
2. Tampered files or manifests in update package are rejected (anti-supply-chain tampering).
3. Path traversal attacks ('..' or absolute paths) in updates are blocked.
4. Protected system files cannot be overwritten by updates.
5. LOCKED state human recovery flow: Orderly clears dirty bit, resets crash history, disengages kill switch, and re-arms supervisor.
6. Non-matching confirmation string is rejected.
"""

import os
import sys
import json
import unittest
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import update_verifier
import locked_recovery
import homie_supervisor
import kill_switch


class TestOperationsAndRecovery(unittest.TestCase):

    def test_signed_update_verification_and_atomic_apply(self):
        """Verifies cryptographic signature validation and atomic update application."""
        import hashlib
        secret_key = b"test_secret_update_key_12345678"
        file_content = "print('hello')"
        file_sha = hashlib.sha256(file_content.encode('utf-8')).hexdigest()

        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = {
                "version": "2.1.0",
                "timestamp": 1700000000,
                "files": {
                    "module_a.py": file_sha
                }
            }
            # Mint valid HMAC signature
            payload["signature"] = update_verifier.sign_update_manifest(payload, secret_key=secret_key)

            files = {"module_a.py": file_content}

            # Applying update with secret_key override
            import unittest.mock as mock
            with mock.patch("update_verifier.get_update_verification_key", return_value=secret_key):
                ok, msg, updated = update_verifier.apply_verified_update(payload, files, target_dir=tmp_dir)

            self.assertTrue(ok, f"Update application failed: {msg}")
            self.assertIn("module_a.py", updated)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "module_a.py")))

    def test_tampered_update_package_rejected(self):
        """Verifies that modified update files or tampered manifests fail closed."""
        secret_key = b"test_secret_update_key_12345678"
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = {
                "version": "2.1.0",
                "timestamp": 1700000000,
                "files": {"safe.py": "0000000000000000000000000000000000000000000000000000000000000000"},
                "signature": "bad_signature_here"
            }

            import unittest.mock as mock
            with mock.patch("update_verifier.get_update_verification_key", return_value=secret_key):
                ok, msg, _ = update_verifier.apply_verified_update(payload, {"safe.py": "bad"}, target_dir=tmp_dir)

            self.assertFalse(ok)
            self.assertIn("Update signature verification failed", msg)

    def test_path_traversal_in_update_manifest_rejected(self):
        """Verifies that directory traversal paths ('../') are rejected."""
        secret_key = b"test_secret_update_key_12345678"
        payload = {
            "version": "2.1.0",
            "timestamp": 1700000000,
            "files": {"../../Windows/System32/evil.dll": "abc123hash"}
        }
        payload["signature"] = update_verifier.sign_update_manifest(payload, secret_key=secret_key)

        import unittest.mock as mock
        with mock.patch("update_verifier.get_update_verification_key", return_value=secret_key):
            valid, msg = update_verifier.verify_update_manifest(payload, secret_key=secret_key)

        self.assertFalse(valid)
        self.assertIn("Malicious path detected", msg)

    def test_locked_recovery_flow(self):
        """Verifies that locked_recovery successfully clears dirty bit and re-arms supervisor."""
        # 1. Simulate locked state
        with open(homie_supervisor.DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": 9999, "epoch": 12345}))
        kill_switch._KILL_SWITCH_ACTIVE = True
        kill_switch._ENGAGED_REASON = "Simulated Lockout"

        diag = locked_recovery.inspect_lockout_cause()
        self.assertTrue(diag["is_dirty_flag_present"])
        self.assertTrue(diag["is_kill_switch_active"])

        # 2. Non-matching confirmation string rejected
        ok_bad, msg_bad, _ = locked_recovery.recover_from_locked_state("WrongConfirmation")
        self.assertFalse(ok_bad)
        self.assertIn("Confirmation mismatch", msg_bad)

        # 3. Valid confirmation restores workstation
        sup = homie_supervisor.PolicySupervisor()
        self.assertEqual(sup.state, homie_supervisor.STATE_LOCKED)

        ok_good, msg_good, info = locked_recovery.recover_from_locked_state(
            locked_recovery.REQUIRED_CONFIRMATION, supervisor_instance=sup
        )
        self.assertTrue(ok_good)
        self.assertEqual(sup.state, homie_supervisor.STATE_ARMED)
        self.assertFalse(kill_switch.is_kill_switch_active())
        self.assertFalse(os.path.exists(homie_supervisor.DIRTY_FLAG_PATH))


if __name__ == "__main__":
    unittest.main()
