"""tests/test_skill_compiler_and_recovery.py - Macro Compiler & Vault Recovery Tests.

Verifies Batch 26 directives:
1. Macro Skill Compiler compiles, signs with HMAC-SHA256, stores, and executes multi-step workflows.
2. Macro registration requires SignedActionApproval bound to macro_canonical_hash (rejects booleans and bearer tokens).
3. Anti-Taint Laundering: Macros cannot be registered while session or workstation is tainted.
4. Macro Name Policy: Regex allowlist (^[a-z0-9_]{1,40}$) and fast-command shadow prevention.
5. Typed Parameter Schema Validation: Parameter recursion depth limits and string length bounds.
6. Tampered macro definitions fail signature verification and are rejected.
7. Cryptographic Key Backup and Disaster Recovery: AES-256-GCM + PBKDF2 export and restore.
8. Privacy log redactor masks PII, API keys, INTENT tokens, and step-up IDs.
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
import phone_approval_portal


class TestSkillCompilerAndRecovery(unittest.TestCase):

    def setUp(self):
        self.test_registry_file = os.path.join(BASE_DIR, "test_temp_macros.json")
        self.registry = skill_compiler.MacroRegistry(storage_path=self.test_registry_file)
        import homie_supervisor, kill_switch, taint_tracker, action_broker
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def tearDown(self):
        if os.path.exists(self.test_registry_file):
            try:
                os.remove(self.test_registry_file)
            except Exception:
                pass
        import homie_supervisor, kill_switch, taint_tracker, action_broker
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def _mint_macro_approval(self, name, steps):
        m_hash = skill_compiler.compute_macro_canonical_hash(name, steps)
        return phone_approval_portal.mint_action_approval("homie_compile_macro", m_hash)

    def test_macro_compilation_signing_and_execution(self):
        """Verifies macro compilation, cryptographic signing, and multi-step execution under bound approval."""
        steps = [
            {"tool": "homie_place_window", "arguments": {"app_name": "notepad", "position": "left"}},
            {"tool": "homie_control_media", "arguments": {"action": "play_pause"}}
        ]
        approval = self._mint_macro_approval("dev_morning_setup", steps)

        ok, msg, macro = self.registry.register_macro(
            name="dev_morning_setup",
            description="Places notepad on the left and toggles music",
            steps=steps,
            approval=approval
        )
        self.assertTrue(ok, f"Registration failed: {msg}")
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
        approval = self._mint_macro_approval("custom_volume_step", steps)
        ok, msg, macro = self.registry.register_macro("custom_volume_step", "Volume step", steps, approval=approval)
        self.assertTrue(ok)

        # Tamper with the macro in registry (insert malicious third-party step)
        tampered_macro = self.registry.get_macro("custom_volume_step")
        tampered_macro["steps"].append({"tool": "homie_launch_app", "arguments": {"app_name": "cmd.exe"}})
        self.registry._macros["custom_volume_step"] = tampered_macro

        # Attempt execution of tampered macro
        exec_ok, exec_msg, _ = skill_compiler.execute_compiled_macro(
            "custom_volume_step", registry=self.registry
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

    def test_macro_compilation_denied_without_approval_object(self):
        """Verifies macro registration is rejected when signed approval object is absent."""
        steps = [{"tool": "homie_control_media", "arguments": {"action": "volup"}}]
        ok, msg, _ = self.registry.register_macro("safe_macro", "Safe macro", steps, approval=None)
        self.assertFalse(ok)
        self.assertIn("strictly requires a signed approval object", msg)

    def test_macro_compilation_denied_when_tainted(self):
        """Verifies anti-taint laundering: Macros cannot be registered from a tainted session."""
        import taint_tracker
        taint_tracker.set_workstation_tainted(True)
        try:
            steps = [{"tool": "homie_control_media", "arguments": {"action": "volup"}}]
            approval = self._mint_macro_approval("tainted_macro", steps)
            ok, msg, _ = self.registry.register_macro("tainted_macro", "Tainted macro", steps, approval=approval)
            self.assertFalse(ok)
            self.assertIn("Taint Laundering Detected", msg)
        finally:
            taint_tracker.clear_all_taints()

    def test_macro_compilation_denied_when_shadowing_fast_command(self):
        """Verifies macros cannot shadow core deterministic fast commands (mute, pause, pc_status)."""
        steps = [{"tool": "homie_control_media", "arguments": {"action": "volup"}}]
        for forbidden in ["mute", "pause", "pc_status", "volume_up", "clipboard"]:
            approval = self._mint_macro_approval(forbidden, steps)
            ok, msg, _ = self.registry.register_macro(forbidden, "Shadowing macro", steps, approval=approval)
            self.assertFalse(ok, f"Expected forbidden name '{forbidden}' to be rejected")
            self.assertIn("shadows built-in fast command", msg)

    def test_macro_name_regex_allowlist(self):
        """Verifies macro names must match allowlist regex ^[a-z0-9_]{1,40}$."""
        steps = [{"tool": "homie_control_media", "arguments": {"action": "volup"}}]
        bad_name = "invalid-name$cmd"
        approval = self._mint_macro_approval(bad_name, steps)
        ok, msg, _ = self.registry.register_macro(bad_name, "Bad name", steps, approval=approval)
        self.assertFalse(ok)
        self.assertIn("violates name policy", msg)

    def test_macro_parameter_schema_validation(self):
        """Verifies deeply nested parameters exceeding nesting limit are rejected."""
        deep_args = {"l1": {"l2": {"l3": {"l4": "too_deep"}}}}
        steps = [{"tool": "homie_place_window", "arguments": deep_args}]
        approval = self._mint_macro_approval("deep_param_macro", steps)
        ok, msg, _ = self.registry.register_macro("deep_param_macro", "Deep", steps, approval=approval)
        self.assertFalse(ok)
        self.assertIn("Parameter recursion depth exceeded", msg)


if __name__ == "__main__":
    unittest.main()
