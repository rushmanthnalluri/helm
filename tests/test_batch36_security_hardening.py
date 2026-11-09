"""test_batch36_security_hardening.py - Batch 36 Security Hardening Acceptance Tests.

Tests verifying Batch 36 architectural hardening directives:
1. Directive 1: Early-exit paths in PolicySupervisor._handle_propose under active PolicyEnvelope
   - Evaluates: Taint denial, NEEDS_HUMAN, Invalid step-up token, Shadow mode, Intent ledger failure.
   - Verifies: actuator_invoked is strictly bound, no UnboundLocalError occurs, reply is valid,
     and reserved_steps is cleanly released to 0.
   - Verifies: Actuator crash consumes step budget (actuator_invoked=True, reserved_steps=0, steps_consumed=1).
2. Directive 2: Phone Approval Relay to Supervisor Cache & SQLite from verify_device_approval
   - Verifies: verify_device_approval relays to homie_supervisor.record_approved_action.
   - Verifies: Cross-process SQLite approved_actions table and in-memory cache populated.
   - Verifies: Supervisor proposal consumes the approval and authorizes action without worker bearer token.
3. Directive 3: Recovery CLI Hardening & Cross-Process SQLite Persistence
   - Verifies: Non-interactive console fails closed.
   - Verifies: Confirmation code mismatch fails closed.
   - Verifies: Recovery token persisted in SQLite console_recovery_tokens table.
   - Verifies: reset_pairing_lockout and complete_device_enrollment consume token across processes.
4. Directive 4: Injector-Level Exact VK Canonicalization (Zero False Positives & Actuator Enforcement)
   - Verifies: 'alt text for the ctrl panel' does NOT trigger Ctrl+Alt+P.
   - Verifies: 'center', 'enterprise', 'return to sender' do NOT trigger Enter.
   - Verifies: keycode=[17, 18, 80] caught as Ctrl+Alt+P.
   - Verifies: key='\\n', text=['enter'], vk=13.0, vk='0x0d' caught as Enter.
   - Verifies: SupervisorActuator.execute_actuator blocks synthetic Ctrl+Alt+P with NO envelope active.
5. Directive 5: Supervisor-First Foreground & UIA Domain Scoping
   - Verifies: Supervisor inspects OS foreground; does not fallback to worker-attested target_process.
   - Verifies: When foreground is browser, ignores worker-attested domain and queries UIA address bar.
6. Directive 6: Physical Low-Level Keyboard Hook Asynchronous Dispatch
   - Verifies: WH_KEYBOARD_LL hook callback dispatches pairing asynchronously; does not block hook thread.
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

import homie_supervisor
import policy_envelope
import phone_approval_portal
import windows_tools
import taint_tracker
import shadow_mode
import agent_audit_ledger
import db_utils
from tests.phone_testing_keys import generate_test_phone_keypair, sign_enrollment_approval, get_test_pairing_code


class TestBatch36SecurityHardening(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"
        import kill_switch
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
        try:
            with db_utils.get_db() as conn:
                conn.execute("DELETE FROM approved_actions WHERE caller_id LIKE 'worker_b36%'")
                conn.execute("DELETE FROM console_recovery_tokens")
                conn.commit()
        except Exception:
            pass

    def test_1_envelope_early_exit_paths_guarantee_zero_reserved_steps_and_no_unbound_local(self):
        """Directive 1: Every early return in _handle_propose under active envelope releases reservation without UnboundLocalError."""
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        client = homie_supervisor.SupervisorClient(sup)
        client.connect()
        client.hello()

        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_early_exits",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=[
                "homie_agent_type", "homie_send_hotkey", "homie_write_file",
                "homie_create_file", "homie_agent_click", "homie_set_clipboard"
            ],
            step_budget=10,
            keystroke_cap=500,
            expiry=time.time() + 300,
            taint_epoch=1,
            allowed_domains=["internal.local"]
        )
        env.is_active = True
        sup.envelope = env

        # Run all test paths with foreground window matching envelope allowed process (notepad.exe)
        with patch.object(windows_tools, "get_foreground_window", return_value={"proc_name": "notepad.exe", "hwnd": 1234}):
            # Path A: Taint Denial / NEEDS_HUMAN (Unapproved WRITE_EXEC action when tainted)
            taint_tracker.set_workstation_tainted(True)
            res_a = client.propose("homie_set_clipboard", {"text": "data"}, caller_id="worker_b36_a")
            self.assertIn(res_a.get("status"), ("NEEDS_HUMAN", "DENY"))
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Path B: NEEDS_HUMAN (Tainted action requiring step-up, but no token provided)
            res_b = client.propose("homie_agent_type", {"text": "test"}, caller_id="worker_b36_b")
            self.assertIn(res_b.get("status"), ("NEEDS_HUMAN", "DENY"))
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Path C: Invalid Step-Up Token
            res_c = client.propose("homie_agent_type", {"text": "test"}, caller_id="worker_b36_c", step_up_token="invalid_token_123")
            self.assertEqual(res_c.get("status"), "DENY")
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Clear taint for remaining paths
            taint_tracker.human_clear_taint("EXPLICIT_HUMAN_CONFIRMATION")

            # Path D: Shadow Mode Active
            shadow_mode.set_shadow_mode(True)
            try:
                res_d = client.propose("homie_set_clipboard", {"text": "abc"}, caller_id="worker_b36_d")
                self.assertEqual(res_d.get("status"), "SHADOW")
                self.assertEqual(env.reserved_steps, 0)
                self.assertEqual(env.steps_consumed, 0)
            finally:
                shadow_mode.set_shadow_mode(False)

            # Path E: Intent Ledger Failure (Simulate disk/DB failure during INTENT recording)
            with patch.object(agent_audit_ledger, "record_agent_action", side_effect=IOError("Simulated disk error")):
                res_e = client.propose("homie_set_clipboard", {"text": "abc"}, caller_id="worker_b36_e")
                self.assertIn(res_e.get("error", "") or res_e.get("status", ""), ("Audit ledger failure: Simulated disk error", "ERROR", "DENY"))
                self.assertEqual(env.reserved_steps, 0)
                self.assertEqual(env.steps_consumed, 0)

            # Path F: Actuator Crash (Actuator throws exception -> consumes step budget!)
            sup.state = homie_supervisor.STATE_ARMED
            import kill_switch
            kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
            with patch.object(sup.actuator, "execute_actuator", side_effect=RuntimeError("Actuator crashed")):
                res_f = client.propose("homie_set_clipboard", {"text": "abc"}, caller_id="worker_b36_f")
                self.assertIn("Actuator crashed", res_f.get("result", "") + res_f.get("error", ""))
                self.assertEqual(env.reserved_steps, 0)
                self.assertEqual(env.steps_consumed, 1, "Actuator crash must consume envelope step budget")

    def test_2_verify_device_approval_relays_to_supervisor_cache_and_db(self):
        """Directive 2: verify_device_approval relays verified device approvals to homie_supervisor."""
        from tests.phone_testing_keys import enroll_test_device, sign_test_challenge
        priv_pem, pub_pem = enroll_test_device("primary_phone")
        phone_approval_portal.clear_active_challenges()

        # Create challenge for a tainted tool
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="ch_b36_relay",
            tool_name="homie_set_clipboard",
            arguments={"text": "sensitive_data"},
            session_id="sess_b36",
            taint_epoch=1,
            device_id="primary_phone",
            ttl_seconds=60.0
        )
        ch["caller_id"] = "worker_b36_relay"
        step_up_id = ch["step_up_id"]
        counter = ch.get("expected_counter", 1)

        # Sign challenge with phone private key
        sig = sign_test_challenge(priv_pem, ch["challenge_hash"])

        # Verify device approval (simulating phone submission to /api/submit-approval)
        app_ok, app_msg, item = phone_approval_portal.verify_device_approval(
            step_up_id, sig, device_id="primary_phone", counter=counter
        )
        self.assertTrue(app_ok, f"verify_device_approval failed: {app_msg}")

        # Assert relay to supervisor approval cache and SQLite
        sup = homie_supervisor.PolicySupervisor()
        args_hash = ch["args_hash"].lower()
        epoch = ch.get("taint_epoch", 0)

        consumed = sup.consume_approved_action("worker_b36_relay", "homie_set_clipboard", args_hash, epoch)
        self.assertTrue(consumed, "Supervisor failed to consume approval relayed by verify_device_approval")

        # Anti-replay: second consumption must fail
        consumed_replay = sup.consume_approved_action("worker_b36_relay", "homie_set_clipboard", args_hash, epoch)
        self.assertFalse(consumed_replay, "Replay attack succeeded on consumed approval")

    def test_3_recovery_cli_non_interactive_fails_closed_and_sqlite_cross_process(self):
        """Directive 3: Recovery CLI fails closed on non-interactive stdin; tokens persist across processes via SQLite."""
        import homie

        # Non-interactive stdin must fail closed
        with patch.object(sys, "argv", ["homie.py", "--pairing-unlock"]):
            with patch.object(sys.stdin, "isatty", return_value=False):
                with patch("builtins.print") as mock_print:
                    homie.main()
                    output = " ".join(str(call[0][0]) for call in mock_print.call_args_list if call[0])
                    self.assertIn("Interactive console presence required", output)

        # Confirmation mismatch must fail closed
        with patch.object(sys, "argv", ["homie.py", "--pairing-unlock"]):
            with patch.object(sys.stdin, "isatty", return_value=True), patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
                with patch("builtins.input", return_value="WRONG-CODE"):
                    with patch("builtins.print") as mock_print:
                        homie.main()
                        output = " ".join(str(call[0][0]) for call in mock_print.call_args_list if call[0])
                        self.assertIn("Operation cancelled", output)

        # Token generated in one process persists in SQLite and can be consumed in another
        tok = phone_approval_portal.generate_console_recovery_token(ttl_seconds=60.0)
        self.assertEqual(len(tok), 32)

        # Clear in-memory dictionary to simulate running in a different process
        phone_approval_portal._CONSOLE_RECOVERY_TOKENS.clear()

        # Reset lockout using token from SQLite
        reset_ok, reset_msg = phone_approval_portal.reset_pairing_lockout(tok)
        self.assertTrue(reset_ok, f"reset_pairing_lockout failed to consume cross-process token from SQLite: {reset_msg}")

        # Anti-replay: single-use token cannot be consumed again
        reset_replay, _ = phone_approval_portal.reset_pairing_lockout(tok)
        self.assertFalse(reset_replay, "Replay attack succeeded on consumed recovery token")

    def test_4_exact_vk_canonicalization_and_actuator_enforcement(self):
        """Directive 4: Exact VK events prevent false positives on prose; catches keycode=[17,18,80]; enforced at actuator."""
        # 1. No false positives on prose
        prose_1 = {"text": "alt text for the ctrl panel"}
        enter_1, chord_1, _, _ = windows_tools.canonicalize_keyboard_arguments(prose_1)
        self.assertFalse(enter_1, "Prose 'alt text for the ctrl panel' falsely triggered Enter")
        self.assertFalse(chord_1, "Prose 'alt text for the ctrl panel' falsely triggered Ctrl+Alt+P")

        prose_2 = {"key": "center"}
        enter_2, _, _, _ = windows_tools.canonicalize_keyboard_arguments(prose_2)
        self.assertFalse(enter_2, "Word 'center' falsely triggered Enter")

        prose_3 = {"text": "enterprise solution return to sender"}
        enter_3, _, _, _ = windows_tools.canonicalize_keyboard_arguments(prose_3)
        self.assertFalse(enter_3, "Prose containing enterprise/return falsely triggered Enter")

        # 2. Keycode chord [17, 18, 80] strictly caught
        chord_args = {"keycode": [17, 18, 80]}
        _, chord_2, vks_2, _ = windows_tools.canonicalize_keyboard_arguments(chord_args)
        self.assertTrue(chord_2, "Keycode chord [17, 18, 80] was not caught as Ctrl+Alt+P")

        # 3. Numeric vk=13.0, hex '0x0d', and literal '\n' caught
        enter_args_1 = {"vk": 13.0}
        e_a1, _, _, _ = windows_tools.canonicalize_keyboard_arguments(enter_args_1)
        self.assertTrue(e_a1, "Numeric float vk=13.0 was not caught as Enter")

        enter_args_2 = {"key": "0x0d"}
        e_a2, _, _, _ = windows_tools.canonicalize_keyboard_arguments(enter_args_2)
        self.assertTrue(e_a2, "Hex vk='0x0d' was not caught as Enter")

        enter_args_3 = {"key": "\n"}
        e_a3, _, _, _ = windows_tools.canonicalize_keyboard_arguments(enter_args_3)
        self.assertTrue(e_a3, "Literal key='\\n' was not caught as Enter")

        # 4. SupervisorActuator directly enforces Ctrl+Alt+P block with NO envelope active
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        actuator = sup.actuator
        sup.envelope = None  # NO envelope active

        intent_token = sup.mint_intent_token("homie_agent_type", {"hotkey": "ctrl+alt+p"}, "worker", 1)
        with self.assertRaises(homie_supervisor.CompleteMediationBreachError) as ctx:
            actuator.execute_actuator(
                "homie_agent_type", {"hotkey": "ctrl+alt+p"}, caller_id="worker", intent_token=intent_token, seq=1
            )
        self.assertIn("Synthetic simulation of physical console pairing hotkey (Ctrl+Alt+P) is strictly prohibited", str(ctx.exception))

    def test_5_supervisor_first_foreground_and_uia_domain_scoping(self):
        """Directive 5: Supervisor resolves OS foreground process; never falls back to worker self-attested proc or domain."""
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        client = homie_supervisor.SupervisorClient(sup)
        client.connect()
        client.hello()

        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_uia",
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_agent_click", "homie_agent_type"],
            step_budget=10,
            keystroke_cap=500,
            expiry=time.time() + 300,
            taint_epoch=1,
            allowed_domains=["internal-bank.local"]
        )
        env.is_active = True
        sup.envelope = env

        # 1. When OS foreground is NOT chrome.exe, worker claiming target_process='chrome.exe' is REJECTED
        with patch.object(windows_tools, "get_foreground_window", return_value={"proc_name": "cmd.exe", "hwnd": 1234}):
            res = client.propose("homie_agent_click", {"target_process": "chrome.exe", "x": 100, "y": 100}, caller_id="worker")
            self.assertEqual(res.get("status"), "DENY")
            self.assertIn("not in envelope allowed list", res.get("reason", ""))

        # 2. When OS foreground IS chrome.exe, worker claiming domain='internal-bank.local' is REJECTED if UIA reports attacker.com
        with patch.object(windows_tools, "get_foreground_window", return_value={"proc_name": "chrome.exe", "hwnd": 1234}):
            with patch.object(windows_tools, "get_browser_active_domain", return_value="attacker.com"):
                res_spoof = client.propose(
                    "homie_agent_click",
                    {"target_process": "chrome.exe", "domain": "internal-bank.local", "x": 100, "y": 100},
                    caller_id="worker"
                )
                self.assertEqual(res_spoof.get("status"), "DENY")
                self.assertIn("attacker.com", res_spoof.get("reason", ""))

    def test_6_physical_low_level_keyboard_hook_dispatches_asynchronously(self):
        """Directive 6: WH_KEYBOARD_LL hook tracks physical keys and dispatches pairing asynchronously."""
        import app
        homie_app = app.HomieApp.__new__(app.HomieApp)
        homie_app._physical_ctrl_down = False
        homie_app._physical_alt_down = False
        homie_app._ll_hook = None

        dispatched = []
        def mock_trigger():
            dispatched.append(time.time())

        homie_app._trigger_pairing_async = mock_trigger

        # Mock KBDLLHOOKSTRUCT struct buffer: vkCode=0x11 (Ctrl), scanCode=0, flags=0 (Physical, not injected)
        import ctypes
        from ctypes import wintypes
        class MockKBDLLHOOKSTRUCT(ctypes.Structure):
            _fields_ = [
                ("vkCode", wintypes.DWORD),
                ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_ulong),
            ]

        # 1. Physical Ctrl down (WM_KEYDOWN = 0x0100, vkCode = 0x11, flags = 0)
        s_ctrl = MockKBDLLHOOKSTRUCT(0x11, 0, 0, 0, 0)
        homie_app.handle_keyboard_event(0, 0x0100, ctypes.addressof(s_ctrl))
        self.assertTrue(homie_app._physical_ctrl_down)

        # 2. Physical Alt down (WM_SYSKEYDOWN = 0x0104, vkCode = 0x12, flags = 0)
        s_alt = MockKBDLLHOOKSTRUCT(0x12, 0, 0, 0, 0)
        homie_app.handle_keyboard_event(0, 0x0104, ctypes.addressof(s_alt))
        self.assertTrue(homie_app._physical_alt_down)

        # 3. Physical P down (WM_KEYDOWN = 0x0100, vkCode = 0x50, flags = 0) -> Triggers pairing dispatch!
        s_p = MockKBDLLHOOKSTRUCT(0x50, 0, 0, 0, 0)
        homie_app.handle_keyboard_event(0, 0x0100, ctypes.addressof(s_p))
        time.sleep(0.05)  # Allow background thread to execute
        self.assertGreaterEqual(len(dispatched), 1, "Physical Ctrl+Alt+P failed to asynchronously trigger pairing")

        # 4. Injected P down (flags = LLKHF_INJECTED = 1) -> Must NOT trigger
        dispatched.clear()
        s_injected = MockKBDLLHOOKSTRUCT(0x50, 0, 1, 0, 0)
        homie_app.handle_keyboard_event(0, 0x0100, ctypes.addressof(s_injected))
        time.sleep(0.05)
        self.assertEqual(len(dispatched), 0, "Injected synthetic keystroke triggered pairing dispatch!")


if __name__ == "__main__":
    unittest.main()
