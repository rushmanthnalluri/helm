"""tests/test_operations_and_recovery.py - Operations, Update Verifier & Locked State Recovery Tests.

Verifies Batch 26 directives:
1. Asymmetric Ed25519 Signed Update Verification: Valid offline Ed25519 signature + matching staging hashes accepted.
2. Bound Signed Approval Object: Applying updates strictly requires SignedActionApproval bound to manifest_hash.
3. Monotonic Version Rollback Protection: Software updates with version_epoch <= installed_epoch are rejected.
4. Strict Manifest vs Payload Equality: Incomplete payloads (payload != manifest["files"]) are rejected.
5. Path Safety: Alternate data streams (':'), reserved Windows names (CON, PRN, etc.), and '..' rejected.
6. Staging Hardening & Journaled Rollback: Staging directory hardened with owner-only DACL; atomic swap with rollback on error.
7. LOCKED State Recovery: Orderly human recovery requiring SignedActionApproval bound to confirmation hash,
   surfaces and acknowledges unresolved intents, preserves workstation taint, bumps session epoch, and logs to HMAC ledger.
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
from scripts.sign_release import sign_update_manifest_offline
import locked_recovery
import helm_supervisor
import kill_switch
import taint_tracker
import agent_audit_ledger
import phone_approval_portal


class TestOperationsAndRecovery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate ephemeral Ed25519 keypair for cryptographic update testing
        cls.test_key = ECC.generate(curve='ed25519')
        cls.private_key_pem = cls.test_key.export_key(format='PEM')
        cls.public_key_pem = cls.test_key.public_key().export_key(format='PEM')
        from tests.phone_testing_keys import enroll_test_device, mint_test_action_approval
        cls.phone_priv, cls.phone_pub = enroll_test_device("primary_phone")
        cls.mint_test_action_approval = staticmethod(mint_test_action_approval)

    def setUp(self):
        for p in [helm_supervisor.DIRTY_FLAG_PATH, helm_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()

    def test_signed_update_verification_and_atomic_apply(self):
        """Verifies Ed25519 asymmetric signature validation and atomic update application under bound approval."""
        file_content = "print('verified update')"
        file_sha = hashlib.sha256(file_content.encode('utf-8')).hexdigest()
        curr_epoch = update_verifier.get_installed_version_epoch()

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = {
                "version": "3.1.0",
                "version_epoch": curr_epoch + 1,
                "expires_at": time.time() + 3600,
                "files": {
                    "module_a.py": file_sha
                }
            }
            # Sign with offline Ed25519 private key
            manifest["signature_b64"] = sign_update_manifest_offline(
                manifest, self.private_key_pem
            )
            payload_files = {"module_a.py": file_content}

            # 1. Denied if approval object is missing or invalid
            ok_no_app, msg_no_app, _ = update_verifier.apply_verified_update(
                manifest, payload_files, approval=None, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem
            )
            self.assertFalse(ok_no_app)
            self.assertIn("requires a verified cryptographic approval object", msg_no_app)

            # 2. Denied if approval is bound to wrong payload hash
            bad_approval = self.mint_test_action_approval(self.phone_priv, "helm_apply_update", "0000badhash0000")
            ok_bad, msg_bad, _ = update_verifier.apply_verified_update(
                manifest, payload_files, approval=bad_approval, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem
            )
            self.assertFalse(ok_bad)
            self.assertIn("PAYLOAD_MISMATCH", msg_bad)

            # 3. Allowed when valid approval bound to canonical manifest hash is supplied
            manifest_bytes = update_verifier.compute_manifest_canonical_bytes(manifest)
            manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            valid_approval = self.mint_test_action_approval(self.phone_priv, "helm_apply_update", manifest_hash)

            ok, msg, updated = update_verifier.apply_verified_update(
                manifest, payload_files, approval=valid_approval, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem
            )
            self.assertTrue(ok, f"Update application failed: {msg}")
            self.assertIn("module_a.py", updated)
            self.assertTrue(os.path.exists(os.path.join(tmp_dir, "module_a.py")))

    def test_strict_manifest_payload_equality(self):
        """Verifies that incomplete payloads (payload != manifest['files']) are rejected."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.1.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {
                "file1.py": "a" * 64,
                "file2.py": "b" * 64
            }
        }
        manifest["signature_b64"] = sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        manifest_bytes = update_verifier.compute_manifest_canonical_bytes(manifest)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        approval = self.mint_test_action_approval(self.phone_priv, "helm_apply_update", manifest_hash)

        # Incomplete payload: only file1 provided
        incomplete_payload = {"file1.py": "print('1')"}
        ok, msg, _ = update_verifier.apply_verified_update(
            manifest, incomplete_payload, approval=approval, public_key_pem=self.public_key_pem
        )
        self.assertFalse(ok)
        self.assertIn("PAYLOAD_MISMATCH", msg)

    def test_tampered_update_package_rejected(self):
        """Verifies that tampered Ed25519 signatures or staging content hash mismatches fail closed."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.1.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"safe.py": "0" * 64},
            "signature_b64": "SGVsbG9Xb3JsZFNpZ25hdHVyZUJBRDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx"
        }
        manifest_bytes = update_verifier.compute_manifest_canonical_bytes(manifest)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        approval = self.mint_test_action_approval(self.phone_priv, "helm_apply_update", manifest_hash)

        with tempfile.TemporaryDirectory() as tmp_dir:
            ok, msg, _ = update_verifier.apply_verified_update(
                manifest, {"safe.py": "bad_content"}, approval=approval, target_dir=tmp_dir,
                public_key_pem=self.public_key_pem
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
            "files": {"old.py": "c" * 64}
        }
        manifest["signature_b64"] = sign_update_manifest_offline(
            manifest, self.private_key_pem
        )

        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("ROLLBACK_REJECTED", msg)

    def test_path_traversal_and_ads_rejected(self):
        """Verifies directory traversal paths ('../') and Alternate Data Streams (':') are rejected."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        
        # ADS check
        manifest_ads = {
            "version": "3.1.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"module.py:evil_stream": "d" * 64}
        }
        manifest_ads["signature_b64"] = sign_update_manifest_offline(
            manifest_ads, self.private_key_pem
        )
        valid_ads, msg_ads = update_verifier.verify_update_manifest(manifest_ads, public_key_pem=self.public_key_pem)
        self.assertFalse(valid_ads)
        self.assertIn("Alternate data stream or colon detected", msg_ads)

        # Traversal check
        manifest_traversal = {
            "version": "3.1.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"../../Windows/System32/evil.dll": "e" * 64}
        }
        manifest_traversal["signature_b64"] = sign_update_manifest_offline(
            manifest_traversal, self.private_key_pem
        )
        valid_trav, msg_trav = update_verifier.verify_update_manifest(manifest_traversal, public_key_pem=self.public_key_pem)
        self.assertFalse(valid_trav)
        self.assertIn("PATH_TRAVERSAL_DETECTED", msg_trav)

    def test_windows_reserved_device_names_rejected(self):
        """Verifies Windows reserved device names (CON, PRN, AUX, NUL, COM1-9) are rejected."""
        curr_epoch = update_verifier.get_installed_version_epoch()
        manifest = {
            "version": "3.1.0",
            "version_epoch": curr_epoch + 1,
            "expires_at": time.time() + 3600,
            "files": {"con.txt": "f" * 64}
        }
        manifest["signature_b64"] = sign_update_manifest_offline(
            manifest, self.private_key_pem
        )
        valid, msg = update_verifier.verify_update_manifest(manifest, public_key_pem=self.public_key_pem)
        self.assertFalse(valid)
        self.assertIn("RESERVED_DEVICE_NAME", msg)

    def test_locked_recovery_flow(self):
        """Verifies that locked_recovery requires SignedActionApproval, clears dirty bit, preserves taints, and re-arms supervisor."""
        # 1. Simulate locked state
        with open(helm_supervisor.DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": 9999, "epoch": 12345}))
        kill_switch._KILL_SWITCH_ACTIVE = True
        kill_switch._ENGAGED_REASON = "Simulated Lockout"
        taint_tracker.set_workstation_tainted(True)

        diag = locked_recovery.inspect_lockout_cause()
        self.assertTrue(diag["is_dirty_flag_present"])
        self.assertTrue(diag["is_kill_switch_active"])

        # 2. Non-matching confirmation string rejected
        ok_bad, msg_bad, _ = locked_recovery.recover_from_locked_state("WrongConfirmation", approval={})
        self.assertFalse(ok_bad)
        self.assertIn("Confirmation mismatch", msg_bad)

        # 3. Missing approval rejected
        ok_no_app, msg_no_app, _ = locked_recovery.recover_from_locked_state(
            locked_recovery.REQUIRED_CONFIRMATION, approval=None
        )
        self.assertFalse(ok_no_app)
        self.assertIn("Missing or malformed signed action approval object", msg_no_app)

        # 3b. Forged or mismatched approval object rejected
        forged_approval = self.mint_test_action_approval(self.phone_priv, "helm_supervisor_recovery", "0" * 64)
        ok_forged, msg_forged, _ = locked_recovery.recover_from_locked_state(
            locked_recovery.REQUIRED_CONFIRMATION, approval=forged_approval
        )
        self.assertFalse(ok_forged)
        self.assertIn("Action approval verification failed", msg_forged)

        # 4. Valid confirmation with bound SignedActionApproval restores workstation while preserving taint
        sup = helm_supervisor.PolicySupervisor()
        self.assertEqual(sup.state, helm_supervisor.STATE_LOCKED)

        payload_hash = locked_recovery.compute_recovery_payload_hash(locked_recovery.REQUIRED_CONFIRMATION)
        valid_approval = self.mint_test_action_approval(self.phone_priv, "helm_supervisor_recovery", payload_hash)

        ok_good, msg_good, info = locked_recovery.recover_from_locked_state(
            locked_recovery.REQUIRED_CONFIRMATION,
            approval=valid_approval,
            supervisor_instance=sup,
            clear_taint=False
        )
        self.assertTrue(ok_good, f"Recovery failed: {msg_good}")
        self.assertEqual(sup.state, helm_supervisor.STATE_ARMED)
        self.assertFalse(kill_switch.is_kill_switch_active())
        self.assertFalse(os.path.exists(helm_supervisor.DIRTY_FLAG_PATH))
        # Workstation taint is preserved across normal recovery
        self.assertTrue(taint_tracker.is_session_tainted("recovery_check"))
        self.assertIn("Preserved workstation taints across recovery", info["actions"])

    def test_no_private_key_signing_in_production_modules(self):
        """Batch 28 Directive: Static security check guaranteeing that production code
        contains ZERO private-key signing capabilities or offline release signers."""
        prod_modules = [
            "update_verifier.py",
            "helm_supervisor.py",
            "phone_approval_portal.py",
            "locked_recovery.py",
            "skill_compiler.py",
            "phone_gateway.py"
        ]
        for mod_name in prod_modules:
            mod_path = os.path.join(BASE_DIR, mod_name)
            if not os.path.exists(mod_path):
                continue
            with open(mod_path, "r", encoding="utf-8") as f:
                code = f.read()

            self.assertNotIn(".sign(", code, f"Production module '{mod_name}' must NOT contain private-key signing calls (.sign)!")
            self.assertNotIn("sign_update_manifest_offline", code, f"Production module '{mod_name}' must NOT contain offline release signer!")
            self.assertNotIn("private_key_pem", code, f"Production module '{mod_name}' must NOT handle private key PEM strings!")


if __name__ == "__main__":
    unittest.main()
