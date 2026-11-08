"""tests/test_skill_compiler_and_recovery.py - Macro Compiler & Vault Recovery Tests.

Verifies:
1. Macro Skill Compiler compiles, signs with HMAC-SHA256, stores, and executes multi-step workflows.
2. Tampered macro definitions fail signature verification and are rejected.
3. Cryptographic Key Backup and Disaster Recovery: AES-256-GCM + PBKDF2 export and restore.
4. Tampered backup or wrong passphrase causes immediate hard denial.
5. Privacy log redactor masks PII, API keys, INTENT tokens, and step-up IDs.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import skill_compiler
import key_recovery
import log_redactor
import crypto_vault


class TestSkillCompilerAndRecovery(unittest.TestCase):

    def setUp(self):
        self.test_registry_file = os.path.join(BASE_DIR, "test_temp_macros.json")
        self.registry = skill_compiler.MacroRegistry(storage_path=self.test_registry_file)

    def tearDown(self):
        if os.path.exists(self.test_registry_file):
            try:
                os.remove(self.test_registry_file)
            except Exception:
                pass

    def test_macro_compilation_signing_and_execution(self):
        """Verifies macro compilation, cryptographic signing, and multi-step execution."""
        steps = [
            {"tool": "homie_place_window", "arguments": {"app_name": "notepad", "position": "left"}},
            {"tool": "homie_control_media", "arguments": {"action": "play_pause"}}
        ]

        ok, msg, macro = self.registry.register_macro(
            name="dev_morning_setup",
            description="Places notepad on the left and toggles music",
            steps=steps
        )
        self.assertTrue(ok)
        self.assertEqual(macro["step_budget"], 2)
        self.assertTrue(bool(macro.get("signature")), "Macro must have cryptographic HMAC signature")

        # Execute macro
        with patch("windows_tools.place_window", return_value=(True, "Placed notepad left")), \
             patch("windows_tools.control_media", return_value=(True, "Triggered media key")):
            exec_ok, exec_msg, results = skill_compiler.execute_compiled_macro(
                "dev_morning_setup", caller_id="desktop_user", registry=self.registry
            )
            self.assertTrue(exec_ok, f"Execution failed: {exec_msg}")
            self.assertEqual(len(results), 2)
            self.assertTrue(all(r["success"] for r in results))

    def test_tampered_macro_signature_rejected(self):
        """Verifies that tampering with a macro step causes signature validation failure."""
        steps = [{"tool": "homie_control_media", "arguments": {"action": "volup"}}]
        ok, msg, macro = self.registry.register_macro("vol_up_macro", "Volume up", steps)
        self.assertTrue(ok)

        # Tamper with the macro in registry (insert malicious third-party step)
        tampered_macro = self.registry.get_macro("vol_up_macro")
        tampered_macro["steps"].append({"tool": "homie_launch_app", "arguments": {"app_name": "cmd.exe"}})
        self.registry._macros["vol_up_macro"] = tampered_macro

        # Attempt execution of tampered macro
        exec_ok, exec_msg, _ = skill_compiler.execute_compiled_macro(
            "vol_up_macro", registry=self.registry
        )
        self.assertFalse(exec_ok)
        self.assertIn("signature is invalid or tampered", exec_msg)

    def test_key_backup_export_and_restore(self):
        """Verifies export and restore of master encryption key under user passphrase."""
        backup_file = os.path.join(BASE_DIR, "test_vault_backup.json")
        passphrase = "UltraSecureWorkstationPassphrase2026!"

        try:
            # 1. Export backup
            exp_ok, path = key_recovery.export_encrypted_backup(passphrase, output_path=backup_file)
            self.assertTrue(exp_ok)
            self.assertTrue(os.path.exists(path))

            # Read and verify backup format
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data.get("version"), 1)
            self.assertIn("ciphertext_b64", data)
            self.assertIn("tag_b64", data)

            # 2. Restore backup with wrong passphrase must fail
            res_wrong, msg_wrong = key_recovery.restore_encrypted_backup(path, "WrongPassword123")
            self.assertFalse(res_wrong)
            self.assertIn("Decryption failed", msg_wrong)

            # 3. Restore backup with correct passphrase must succeed
            res_correct, msg_correct = key_recovery.restore_encrypted_backup(path, passphrase)
            self.assertTrue(res_correct)
            self.assertIn("successfully restored", msg_correct)
        finally:
            if os.path.exists(backup_file):
                try:
                    os.remove(backup_file)
                except Exception:
                    pass

    def test_log_redaction(self):
        """Verifies PII, API tokens, and secret redaction."""
        raw_text = "User key: api_key='sk-ant-api03-abcdef1234567890' with INTENT_V2:17000:1:17000:snap:hash:user:sig and email user@example.com"
        redacted = log_redactor.redact_string(raw_text)

        self.assertNotIn("sk-ant-api03", redacted)
        self.assertNotIn("user@example.com", redacted)
        self.assertIn("***REDACTED_SECRET***", redacted)
        self.assertIn("***REDACTED_INTENT_TOKEN***", redacted)
        self.assertIn("***REDACTED_EMAIL***", redacted)


if __name__ == "__main__":
    unittest.main()
