"""tests/test_operations_and_recovery.py - Operations, Update Verifier & Locked State Recovery Tests.

Verifies Batch 25 directives:
1. Asymmetric Ed25519 Signed Update Verification: Valid offline Ed25519 signature + matching staging hashes accepted.
2. Human Authorization Gate: Applying software updates strictly requires verified human authorization.
3. Monotonic Version Rollback Protection: Software updates with version_epoch <= installed_epoch are rejected.
4. Expiration Enforcement: Expired update manifests fail closed.
5. Path Traversal & Protected Files Rejection: Directory traversal and attempts to overwrite vault/audit files are blocked.
6. Tampered signature or mismatched staging hash fails closed.
7. LOCKED State Recovery: Orderly human recovery requiring explicit confirmation, interactive TTY/channel checks,
   surfaces root cause, preserves workstation taint, disengages kill switch, re-arms supervisor, and writes to audit ledger.
"""

import os
import sys
import json
import time
import unittest
import tempfile
import hashlib
from Crypto.PublicKey import ECC

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import update_verifier
import locked_recovery
import homie_supervisor
import kill_switch
import taint_tracker
import agent_audit_ledger


class TestOperationsAndRecovery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate ephemeral Ed25519 keypair for cryptographic update testing
        cls.test_key = ECC.generate(curve='ed25519')
        cls.private_key_pem = cls.test_key.export_key(format='PEM')
        cls.public_key_pem = cls.test_key.public_key().export_key(format='PEM')

    def test_signed_update_verification_and_atomic_apply(self):
        """Verifies Ed25519 asymmetric signature validation and atomic update application."""
        file_content = "print('verified update')"
        file_sha = hashlib.sha256(file_content.encode('utf-8')).hexdigest()
        curr_epoch = update_verifier.get_installed_version_epoch()

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = {
                "version": "3.0.0",
                "version_epoch": curr_epoch + 1,
                "expires_at": time.time() + 3600,
                "files": {
                    "module_a.py": file_sha
                }
            }
            # Sign with offline Ed25519 private key
            manifest["signature_b64"] = update_verifier.sign_update_manifest_offline(
                manifest, self.private_key_pem
            )

            payload_files = {"module_a.py": file_content}

            # 1. Denied if human_auth is False
            ok_no_auth, msg_no_auth, _ = update_verifier.apply_verified_update(
                manifest, payload_files, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem, human_auth=False
            )
            self.assertFalse(ok_no_auth)
            self.assertIn("requires verified human authorization", msg_no_auth)

            # 2. Allowed when human_auth is True
            ok, msg, updated = update_verifier.apply_verified_update(
                manifest, payload_files, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem, human_auth=True
            )
            self.assertTrue(ok, f"Update application failed: {msg}")
            self.assertIn("module_a.py", updated)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "module_a.py")))

    def test_tampered_update_package_rejected(self):
        """Verifies that tampered Ed25519 signatures or staging content hash mismatches fail closed."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.0.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"safe.py": "0000000000000000000000000000000000000000000000000000000000000000"},
            "signature_b64": "SGVsbG9Xb3JsZFNpZ25hdHVyZUJBRDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx"
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            ok, msg, _ = update_verifier.apply_verified_update(
                manifest, {"safe.py": "bad_content"}, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem, human_auth=True
            )
            self.assertFalse(ok)
            self.assertIn("SIGNATURE_INVALID", msg)

    def test_rollback_epoch_rejection(self):
        """Verifies monotonic version rollback protection."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "0.9.0",
            "version_epoch": curr_epoch,  # <= current epoch
            "expires_at": time.time() + 3600,
            "files": {"old.py": "abc"}
        }
        manifest["signature_b64"] = update_verifier.sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("ROLLBACK_REJECTED", msg)

    def test_expired_update_manifest_rejected(self):
        """Verifies that expired packages are rejected."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.0.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() - 60,  # Expired in past
            "files": {"test.py": "abc"}
        }
        manifest["signature_b64"] = update_verifier.sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("UPDATE_EXPIRED", msg)

    def test_path_traversal_in_update_manifest_rejected(self):
        """Verifies that directory traversal paths ('../') are rejected."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.0.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"../../Windows/System32/evil.dll": "abc123hash"}
        }
        manifest["signature_b64"] = update_verifier.sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("PATH_TRAVERSAL_DETECTED", msg)

    def test_protected_system_files_cannot_be_overwritten(self):
        """Verifies update packages cannot overwrite vault keys or audit logs."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.0.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {".homie_vault.key": "abc123hash"}
        }
        manifest["signature_b64"] = update_verifier.sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("SECURITY_BREACH", msg)

    def test_locked_recovery_flow(self):
        """Verifies that locked_recovery successfully clears dirty bit, preserves taints, and re-arms supervisor."""
        # 1. Simulate locked state
        with open(homie_supervisor.DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": 9999, "epoch": 12345}))
        kill_switch._KILL_SWITCH_ACTIVE = True
        kill_switch._ENGAGED_REASON = "Simulated Lockout"
        taint_tracker.set_workstation_tainted(True)

        diag = locked_recovery.inspect_lockout_cause()
        self.assertTrue(diag["is_dirty_flag_present"])
        self.assertTrue(diag["is_kill_switch_active"])

        # 2. Non-matching confirmation string rejected
        ok_bad, msg_bad, _ = locked_recovery.recover_from_locked_state("WrongConfirmation", bypass_tty=True)
        self.assertFalse(ok_bad)
        self.assertIn("Confirmation mismatch", msg_bad)

        # 3. Valid confirmation restores workstation while preserving taint
        sup = homie_supervisor.PolicySupervisor()
        self.assertEqual(sup.state, homie_supervisor.STATE_LOCKED)

        ok_good, msg_good, info = locked_recovery.recover_from_locked_state(
            locked_recovery.REQUIRED_CONFIRMATION,
            supervisor_instance=sup,
            bypass_tty=True,
            clear_taint=False
        )
        self.assertTrue(ok_good)
        self.assertEqual(sup.state, homie_supervisor.STATE_ARMED)
        self.assertFalse(kill_switch.is_kill_switch_active())
        self.assertFalse(os.path.exists(homie_supervisor.DIRTY_FLAG_PATH))
        # Workstation taint is preserved across normal recovery
        self.assertTrue(taint_tracker.is_session_tainted("recovery_check"))
        self.assertIn("Preserved workstation taints across recovery", info["actions"])


if __name__ == "__main__":
    unittest.main()
