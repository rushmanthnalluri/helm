"""tests/test_batch41_security_hardening.py - Batch 41 Security & Architectural Split Test Suite.

Verifies:
1. Verified mobile signature strictly required when hardware device is enrolled (no local bypass).
2. Physical presence gesture strictly required when no device is enrolled.
3. Out-of-process supervisor failure fail-closed: When supervisor is stopped/killed, every tool fails.
4. UI / broker process holds no HMAC signing secret in pipe mode.
5. Recovery token DACL denies unelevated Delete permission (anti-DoS).
6. WindowFromPoint detects Homie window by application image path (BASE_DIR), defeating title spoofing.
7. Compiled-in safety floor completeness and legacy alias normalization.
"""

import os
import sys
import time
import json
import secrets
import hashlib
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import homie_supervisor
import phone_approval_portal
import device_registry
import rails_config
import rails_confirmation
import action_broker
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    sign_test_challenge,
    mint_test_action_approval
)


class TestBatch41SecurityHardening(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        device_registry.clear_consumed_nonces_for_testing()

    def test_1_verified_mobile_signature_strictly_required_when_device_enrolled(self):
        """Directive 1: When a device is enrolled, confirm() strictly requires valid phone signature."""
        priv_pem, pub_pem = enroll_test_device("batch41_test_phone")

        gate = rails_confirmation.ConfirmationGate()
        req = gate.create_request("homie_set_clipboard", {"text": "classified_data"}, caller_id="assistant")

        # Case A: Confirmation without signed evidence is DENIED
        ok_no_sig, msg_no_sig, tok_no_sig = gate.confirm(req.request_id)
        self.assertFalse(ok_no_sig)
        self.assertIsNone(tok_no_sig)
        self.assertIn("strictly requires verified out-of-band signature", msg_no_sig)

        # Case B: Confirmation with forged/invalid signature is DENIED
        bad_evidence = {
            "device_id": "batch41_test_phone",
            "action_name": "homie_set_clipboard",
            "payload_hash": "deadbeef" * 8,
            "nonce": secrets.token_hex(16),
            "expiry": int(time.time() + 100),
            "taint_epoch": 0,
            "signature": "badf00d" * 8
        }
        ok_bad, msg_bad, tok_bad = gate.confirm(req.request_id, signed_evidence=bad_evidence)
        self.assertFalse(ok_bad)
        self.assertIsNone(tok_bad)
        self.assertIn("Mobile signature verification failed", msg_bad)

        # Case C: Legitimate phone signature is ACCEPTED
        clean_args = json.dumps(req.arguments, sort_keys=True, separators=(',', ':'))
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
        valid_evidence = mint_test_action_approval(
            priv_pem, "homie_set_clipboard", args_hash, device_id="batch41_test_phone"
        )

        ok_valid, msg_valid, tok_valid = gate.confirm(req.request_id, signed_evidence=valid_evidence)
        self.assertTrue(ok_valid)
        self.assertIsNotNone(tok_valid)
        self.assertIn("Action confirmed", msg_valid)

        # Case D: Replay of the same confirmation is DENIED (already consumed / approved)
        ok_replay, _, _ = gate.confirm(req.request_id, signed_evidence=valid_evidence)
        self.assertFalse(ok_replay)

    def test_2_physical_presence_gesture_strictly_required_when_no_device_enrolled(self):
        """Directive 2: When no mobile device is enrolled, confirm() strictly requires physical presence gesture."""
        with patch("device_registry.get_enrolled_devices", return_value={}):
            gate = rails_confirmation.ConfirmationGate()
            req = gate.create_request("homie_launch_app", {"app_name": "calc.exe"})

            # Case A: Confirmation without presence gesture is DENIED
            ok_none, msg_none, _ = gate.confirm(req.request_id)
            self.assertFalse(ok_none)
            self.assertIn("presence challenge gesture required", msg_none.lower())

            # Case B: Confirmation with wrong presence gesture is DENIED
            ok_wrong, msg_wrong, _ = gate.confirm(req.request_id, presence_gesture="000000")
            self.assertFalse(ok_wrong)
            self.assertIn("invalid physical presence", msg_wrong.lower())

            # Case C: Confirmation with matching presence gesture is ACCEPTED
            ok_good, msg_good, tok_good = gate.confirm(req.request_id, presence_gesture=req.presence_challenge)
            self.assertTrue(ok_good)
            self.assertIsNotNone(tok_good)

    def test_3_supervisor_killed_all_channels_fail_closed(self):
        """Directive 3: When out-of-process supervisor is killed/unreachable, all actions fail closed."""
        import kill_switch
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False

        pipe_name = r"\\.\pipe\test_homie_supervisor_b41_" + secrets.token_hex(4)
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        server = homie_supervisor.NamedPipeSupervisorServer(sup, pipe_name=pipe_name)
        server.start()
        time.sleep(0.1)

        try:
            client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
            client.connect(timeout_sec=1.0)
            client.hello()
            broker = action_broker.ActionBroker(pipe_client=client)

            # While server is running, action executes successfully
            ok, msg, res = broker.execute_action("homie_get_vitals", {}, caller_id="desktop_user")
            self.assertTrue(ok, f"Execution failed while supervisor running: {msg}")

            # Disconnect and stop the supervisor server (simulating crash or process kill)
            client.close()
            time.sleep(0.05)
            server.stop()
            sup.clean_shutdown()

            # When supervisor is killed, EVERY channel and tool FAILS CLOSED immediately
            for caller in ["desktop_user", "desktop_voice", "telegram_remote", "phone_gateway", "ai_engine"]:
                ok_dead, msg_dead, _ = broker.execute_action("homie_get_vitals", {}, caller_id=caller)
                self.assertFalse(ok_dead, f"Channel '{caller}' must fail closed when supervisor is dead!")
                self.assertIn("Supervisor process is unreachable or disconnected", msg_dead)

        finally:
            server.stop()
            sup.clean_shutdown()

    def test_4_ui_process_holds_no_signing_secret(self):
        """Directive 4: UI broker in pipe client mode holds no PolicySupervisor instance and no signing secret."""
        pipe_client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=r"\\.\pipe\dummy_test_pipe")
        broker = action_broker.ActionBroker(pipe_client=pipe_client)

        self.assertIsNone(broker.supervisor, "UI broker process must not hold an in-process PolicySupervisor instance!")
        self.assertFalse(hasattr(broker, "intent_secret"), "UI broker process must not hold intent signing secret!")
        self.assertFalse(hasattr(broker, "actuator"), "UI broker process must not hold privileged actuators!")

    def test_5_recovery_token_dacl_denies_unelevated_delete(self):
        """Directive 5: Recovery token DACL grants Users read-only access and denies Delete (anti-DoS)."""
        import phone_approval_portal
        import win32con
        import win32security

        # When write_admin_recovery_token sets security info, verify Users SID lacks DELETE permission
        with patch("win32security.SetNamedSecurityInfo") as mock_sec, \
             patch("builtins.open", MagicMock()):
            phone_approval_portal.write_admin_recovery_token("token_dacl_test_123")
            self.assertTrue(mock_sec.called, "SetNamedSecurityInfo must be invoked")
            # First call is on the token file DACL (arg index 5)
            dacl = mock_sec.call_args_list[0][0][5]
            users_sid = win32security.ConvertStringSidToSid("S-1-5-32-545")
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                mask, sid = ace[1], ace[2]
                if sid == users_sid:
                    self.assertEqual(
                        mask & win32con.DELETE, 0,
                        "Builtin Users SID must NOT possess DELETE permission on recovery token!"
                    )
                    self.assertNotEqual(
                        mask & win32con.GENERIC_READ, 0,
                        "Builtin Users SID must possess GENERIC_READ permission on recovery token."
                    )

    def test_6_windowfrompoint_detects_homie_by_process_path(self):
        """Directive 6: WindowFromPoint detects Homie window by executable path (BASE_DIR), defeating title spoofing."""
        sup = homie_supervisor.PolicySupervisor()
        actuator = homie_supervisor.SupervisorActuator(sup)

        # Mock get_window_under_point to return a window whose title is spoofed ("Notepad")
        # but whose exe_path resides inside D:\homie (BASE_DIR)
        spoofed_window_info = {
            "pid": 99999,
            "proc_name": "python.exe",
            "title": "Notepad - Untitled Document",  # Spoofed innocent title
            "exe_path": os.path.join(BASE_DIR, "homie_ui.exe")
        }

        with patch.object(windows_tools, "get_window_under_point", return_value=(12345, spoofed_window_info)):
            with self.assertRaises(homie_supervisor.CompleteMediationBreachError) as cm:
                actuator.execute_actuator(
                    "homie_agent_click", {"x": 100, "y": 200}, caller_id="desktop_user", seq=1
                )
            self.assertIn("targets Homie application image", str(cm.exception))

    def test_7_compiled_in_safety_floor_comprehensiveness_and_alias_mapping(self):
        """Directive 7: Compiled-in safety floor covers consequential tools and legacy aliases."""
        cfg = rails_config.RailsConfig()

        # All consequential OS-manipulation tools must be in floor
        consequential_set = [
            "homie_set_clipboard", "homie_launch_app", "homie_send_chat",
            "homie_close_app", "homie_kill_process", "homie_safe_command",
            "homie_agent_click", "homie_agent_type"
        ]
        for tool in consequential_set:
            self.assertTrue(cfg.is_confirmation_required(tool), f"Tool '{tool}' must require confirmation!")

        # Legacy aliases in ActionBroker.LEGACY_TOOL_MAP must map into safety floor
        for alias, canonical in action_broker.ActionBroker.LEGACY_TOOL_MAP.items():
            if canonical in consequential_set:
                self.assertTrue(
                    cfg.is_confirmation_required(alias),
                    f"Legacy alias '{alias}' (mapping to '{canonical}') must require confirmation!"
                )


if __name__ == "__main__":
    unittest.main()
