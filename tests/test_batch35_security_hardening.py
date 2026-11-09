"""test_batch35_security_hardening.py - Batch 35 Security Acceptance Tests.

Tests verifying Batch 35 architectural hardening directives:
1. Directive 1: Pinned SPKI DER SHA-256 Fingerprint Pinning (update_verifier.py).
2. Directive 2: Injector-Level Virtual-Key Canonicalization:
   - key="\\n" detected as Enter submit (strip() does not bypass).
   - text=["enter"] and text=["\\n"] detected as Enter submit.
   - keycode=[13], vk=13.0, and vk="0x0d" detected as Enter submit.
   - Synthetic simulation of Ctrl+Alt+P chord strictly rejected.
   - Words "enterprise", "center", "return to sender" remain allowed (no false positives).
3. Directive 3: UNKNOWN Outcomes Consume Envelope Step Budget:
   - Actuator crash/exception consumes step budget (steps_consumed += 1, reserved_steps == 0).
   - Early proposal denial before actuator releases reservation (steps_consumed == 0, reserved_steps == 0).
4. Directive 4: Production Approval Relay to Supervisor Cache and SQLite:
   - phone_approval_portal.verify_action_approval relays to homie_supervisor.record_approved_action.
   - Cross-process SQLite approved_actions table and in-memory cache both populated.
   - homie_supervisor.consume_approved_action successfully consumes.
5. Directive 5: Production Console Callers for generate_console_recovery_token:
   - homie.py CLI commands (--pairing-unlock, --recover-device) call generate_console_recovery_token.
   - Non-interactive invocation fails closed.
6. Directive 6: Physical-Only Low-Level Keyboard Hook in app.py:
   - WH_KEYBOARD_LL hook callback filters LLKHF_INJECTED.
   - Synthetic keystroke injection cannot trigger mobile enrollment.
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

import update_verifier
import policy_envelope
import phone_approval_portal
import homie_supervisor
import windows_tools
from tests.phone_testing_keys import generate_test_phone_keypair, sign_enrollment_approval, get_test_pairing_code


class TestBatch35SecurityHardening(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"
        import kill_switch
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
        try:
            import db_utils
            with db_utils.get_db() as conn:
                conn.execute("DELETE FROM approved_actions WHERE caller_id LIKE 'worker_b35%'")
                conn.commit()
        except Exception:
            pass

    def test_1_pinned_publisher_key_der_sha256_fingerprint(self):
        """Directive 1: Pinned SPKI DER SHA-256 fingerprint matches pinned constant."""
        fingerprint = update_verifier.get_publisher_key_der_hash()
        self.assertEqual(fingerprint, update_verifier.PINNED_PUBLISHER_KEY_SHA256)
        self.assertEqual(len(fingerprint), 64)
        self.assertEqual(update_verifier.PINNED_PUBLISHER_KEY_SHA256, "32278129e14141b57aa28fd6a6888f77b492cdd88e3b7b6229872b7f11e123fb")

        # Verify module enforces publisher key fingerprint assertion
        with open(update_verifier.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn(
            "assert get_publisher_key_der_hash() == PINNED_PUBLISHER_KEY_SHA256",
            src,
            "Publisher key SPKI DER fingerprint assertion missing from update_verifier.py"
        )

    def test_2_injector_level_virtual_key_canonicalization_and_bypass_hardening(self):
        """Directive 2: Canonicalize to VK events; catch key='\\n', text=['enter'], keycode=[13], vk=13.0, and synthetic Ctrl+Alt+P."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_canon",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["homie_agent_type", "homie_send_hotkey", "homie_remote_trackpad"],
            step_budget=5,
            keystroke_cap=500,
            expiry=time.time() + 300,
            taint_epoch=1,
            device_id="phone_1"
        )
        env.is_active = True

        # Case 1: key="\n" (strip() makes empty string, but must be caught)
        ok, msg, _ = env.check_boundary("homie_remote_trackpad", {"action": "key", "key": "\n"}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 2: text=["enter"]
        ok, msg, _ = env.check_boundary("homie_agent_type", {"text": ["enter"], "element_name": "input_box"}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 3: text=["a", "\n"]
        ok, msg, _ = env.check_boundary("homie_agent_type", {"text": ["a", "\n"], "element_name": "input_box"}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 4: keycode=[13]
        ok, msg, _ = env.check_boundary("homie_send_hotkey", {"keycode": [13]}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 5: vk=13.0 (float)
        ok, msg, _ = env.check_boundary("homie_send_hotkey", {"vk": 13.0}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 6: vk="0x0d" (hex string)
        ok, msg, _ = env.check_boundary("homie_send_hotkey", {"vk": "0x0d"}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Enter-to-submit", msg)

        # Case 7: Synthetic Ctrl+Alt+P chord in list format
        ok, msg, _ = env.check_boundary("homie_send_hotkey", {"keys": ["ctrl", "alt", "p"]}, "notepad.exe", 1)
        self.assertFalse(ok)
        self.assertIn("Ctrl+Alt+P", msg)

        # Case 8: Prose words ("enterprise", "center", "return to sender") MUST BE ALLOWED (no false positives)
        allowed_prose = [
            {"text": "enterprise architecture design", "element_name": "doc"},
            {"text": "community center", "element_name": "doc"},
            {"text": "return to sender", "element_name": "doc"},
        ]
        for idx, prose_args in enumerate(allowed_prose):
            ok, msg, _ = env.check_boundary("homie_agent_type", prose_args, "notepad.exe", 1)
            self.assertTrue(ok, f"Prose case {idx} falsely rejected: {msg}")

    def test_3_unknown_outcome_consumes_step_budget(self):
        """Directive 3: UNKNOWN outcomes consume step budget; release reservation ONLY if actuator was never invoked."""
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        client = homie_supervisor.SupervisorClient(supervisor_instance=sup)
        client.connect()
        client.hello()
        client.seq = 100

        import taint_tracker
        current_epoch = taint_tracker.get_taint_epoch()
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_unknown_outcome",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["homie_agent_type"],
            step_budget=5,
            keystroke_cap=500,
            expiry=time.time() + 300,
            taint_epoch=current_epoch,
            device_id="phone_1"
        )
        env.is_active = True
        sup.envelope = env

        # Initial state: 0 consumed, 0 reserved
        self.assertEqual(env.steps_consumed, 0)
        self.assertEqual(env.reserved_steps, 0)

        # Scenario A: Actuator is invoked but throws RuntimeError (outcome: UNKNOWN)
        # The step budget MUST be consumed because the actuator ran side-effects!
        with patch.object(windows_tools, "get_foreground_window", return_value={"proc_name": "notepad.exe", "hwnd": 1234}):
            with patch.object(sup.actuator, 'execute_actuator', side_effect=RuntimeError("Driver crashed mid-typewrite")):
                rep = client.propose("homie_agent_type", {"text": "hello world", "target_process": "notepad.exe"})
                self.assertEqual(rep.get("status"), "DENY")
                self.assertIn("Driver crashed mid-typewrite", rep.get("reason", ""))

        # UNKNOWN outcome must have committed the step!
        self.assertEqual(env.steps_consumed, 1)
        self.assertEqual(env.reserved_steps, 0)

        # Scenario B: Early proposal denial BEFORE actuator invocation (e.g. unknown tool)
        # Reservation must be RELEASED (not committed).
        rep2 = client.propose("unregistered_malicious_tool", {"foo": "bar", "target_process": "notepad.exe"})
        self.assertEqual(rep2.get("status"), "DENY")
        self.assertEqual(env.steps_consumed, 1)  # Still 1, not 2
        self.assertEqual(env.reserved_steps, 0)

    def test_4_production_approval_relay_to_supervisor_cache_and_db(self):
        """Directive 4: verify_action_approval relays directly to homie_supervisor.record_approved_action."""
        priv_pem, pub_pem = generate_test_phone_keypair()
        device_id = "test_phone_b35"

        # Register test device in registry
        reg = phone_approval_portal._load_device_registry()
        reg[device_id] = {
            "public_key": pub_pem,
            "authenticator_type": "device_resident_ed25519",
            "paired_at": time.time(),
            "counter": 0,
            "revoked": False,
            "device_name": "Test Phone"
        }
        phone_approval_portal._save_device_registry(reg)

        # Create signed action approval using standard test helper
        from tests.phone_testing_keys import mint_test_action_approval
        action_name = "homie_set_clipboard"
        payload_hash = "3a7b9c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
        approval_dict = mint_test_action_approval(
            phone_private_key=priv_pem,
            action_name=action_name,
            payload_hash=payload_hash,
            device_id=device_id
        )
        approval_dict["caller_id"] = "worker_b35"

        # Verify approval: should automatically relay to supervisor approval cache
        ok, v_msg = phone_approval_portal.verify_action_approval(approval_dict, action_name, payload_hash)
        self.assertTrue(ok, v_msg)

        # Verify supervisor can consume the approved action
        taint_epoch = approval_dict["taint_epoch"]
        consumed = homie_supervisor.consume_approved_action("worker_b35", action_name, payload_hash, taint_epoch)
        self.assertTrue(consumed, "Supervisor failed to consume relayed action approval")

        # Second consumption must fail (single-use)
        consumed_again = homie_supervisor.consume_approved_action("worker_b35", action_name, payload_hash, taint_epoch)
        self.assertFalse(consumed_again, "Replay attack succeeded on consumed approval")

    def test_5_console_recovery_token_cli_caller(self):
        """Directive 5: homie.py CLI commands (--pairing-unlock, --recover-device) generate recovery tokens."""
        import homie

        # Non-interactive invocation must fail closed
        with patch('sys.argv', ['homie.py', '--pairing-unlock']):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('sys.stdout') as mock_out:
                    homie.main()
                    # Should print security error about console presence
                    self.assertTrue(any("Interactive console presence required" in str(c) for c in mock_out.write.call_args_list))

        # Interactive invocation with confirmation code
        with patch('sys.argv', ['homie.py', '--pairing-unlock']):
            with patch('sys.stdin.isatty', return_value=True):
                with patch('builtins.input', return_value='CONFIRM-RESET'):
                    with patch.object(phone_approval_portal, 'generate_console_recovery_token', wraps=phone_approval_portal.generate_console_recovery_token) as mock_gen:
                        homie.main()
                        self.assertEqual(mock_gen.call_count, 1)

    def test_6_physical_only_low_level_keyboard_hook(self):
        """Directive 6: Low-level keyboard hook callback in app.py strictly ignores injected keystrokes."""
        from app import HomieApp
        app = HomieApp()

        import ctypes
        from ctypes import wintypes
        class KBDLLHOOKSTRUCT(ctypes.Structure):
            _fields_ = [
                ("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_ulong),
            ]

        # Case 1: Injected keystroke (LLKHF_INJECTED = 0x01) targeting Ctrl+Alt+P
        fake_kb_injected = KBDLLHOOKSTRUCT()
        fake_kb_injected.vkCode = 0x50  # VK_P
        fake_kb_injected.flags = 0x00000001  # LLKHF_INJECTED
        lParam_injected = ctypes.addressof(fake_kb_injected)

        with patch('phone_approval_portal.start_local_enrollment') as mock_enroll:
            with patch('ctypes.windll.user32.GetAsyncKeyState', return_value=0x8000):
                app.handle_keyboard_event(0, 0x0100, lParam_injected)
                # Injected keystroke must be IGNORED
                mock_enroll.assert_not_called()

        # Case 2: Physical hardware keystroke (flags = 0) targeting Ctrl+Alt+P
        fake_kb_physical = KBDLLHOOKSTRUCT()
        fake_kb_physical.vkCode = 0x50  # VK_P
        fake_kb_physical.flags = 0  # Physical hardware scan code
        lParam_physical = ctypes.addressof(fake_kb_physical)

        with patch('phone_approval_portal.start_local_enrollment', return_value="sess_test_b35_12345678") as mock_enroll:
            app._physical_ctrl_down = True
            app._physical_alt_down = True
            app.handle_keyboard_event(0, 0x0100, lParam_physical)
            time.sleep(0.05)
            # Physical hardware keystroke MUST trigger enrollment
            mock_enroll.assert_called_once()


if __name__ == "__main__":
    unittest.main()
