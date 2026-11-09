"""tests/test_batch39_security_hardening.py - Batch 39 Hardening Test Suite.

Verifies:
1. Point-under-cursor WindowFromPoint self-targeting defense: synthetic clicks on Homie's window/PID fail closed.
2. Lone Win-key denial: key="win" or keycode=[91] returns "Win" and is denied.
3. Chord canonicalization exact token matching: "ctrl+return" never matches "r", and prose fields do not trip chords.
4. Admin recovery token single-use failure fails closed if unlink fails.
5. Compiled-in safety floor immutability: covers all non-READ_ONLY tools (including fact mutation) and cannot be weakened by disk config.
6. Confirmation gate rejects non-human caller IDs (workers/agents cannot approve their own actions).
"""

import os
import sys
import unittest
import json
import time
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import homie_supervisor
import phone_approval_portal
import rails_config
import rails_confirmation
import agent_tools
import action_broker


class TestBatch39SecurityHardening(unittest.TestCase):

    def test_1_point_under_cursor_windowfrompoint_self_targeting_defense(self):
        """Directive 1: Synthetic click targeting physical coordinates over Homie's window or PID is blocked."""
        sup = homie_supervisor.PolicySupervisor()
        actuator = homie_supervisor.SupervisorActuator(sup)

        # Mock window under point to simulate landing on Homie's assistant window
        mock_info = {
            "pid": os.getpid(),
            "proc_name": "python.exe",
            "title": "Homie Assistant"
        }
        with patch.object(windows_tools, "get_window_under_point", return_value=(12345, mock_info)):
            with self.assertRaises(homie_supervisor.CompleteMediationBreachError) as cm:
                actuator.execute_actuator(
                    "homie_agent_click",
                    {"x": 100, "y": 200},
                    caller_id="worker",
                    seq=1
                )
            self.assertIn("Point-under-cursor", str(cm.exception))

    def test_2_lone_win_key_denial(self):
        """Directive 2: Lone Win key (key='win' or keycode=[91]) returns 'Win' and is blocked."""
        # 1. key='win'
        _, _, vks1, tokens1 = windows_tools.canonicalize_keyboard_arguments({"key": "win"})
        chord1 = windows_tools.detect_blocked_system_chords(vks1, tokens1)
        self.assertEqual(chord1, "Win", "Lone 'win' key must return 'Win'")

        # 2. keycode=[91]
        _, _, vks2, tokens2 = windows_tools.canonicalize_keyboard_arguments({"keycode": [91]})
        chord2 = windows_tools.detect_blocked_system_chords(vks2, tokens2)
        self.assertEqual(chord2, "Win", "Lone keycode 91 must return 'Win'")

        # 3. Lone Win key must be denied by SupervisorActuator
        sup = homie_supervisor.PolicySupervisor()
        actuator = homie_supervisor.SupervisorActuator(sup)
        with self.assertRaises(homie_supervisor.CompleteMediationBreachError) as cm:
            actuator.execute_actuator("homie_agent_type", {"key": "win"}, caller_id="worker", seq=1)
        self.assertIn("Win", str(cm.exception))

    def test_3_exact_token_matching_without_substring_ambiguity(self):
        """Directive 3: 'ctrl+return' does NOT match 'r', and prose text does NOT trip chords."""
        # 1. ctrl+return must NOT trip has_r
        _, _, vks1, tokens1 = windows_tools.canonicalize_keyboard_arguments({"hotkey": "ctrl+return"})
        chord1 = windows_tools.detect_blocked_system_chords(vks1, tokens1)
        self.assertIsNone(chord1, f"ctrl+return must not be blocked as a dangerous chord, got: {chord1}")

        # 2. prose text containing 'win a prize ... r' must NOT trip Win+R
        _, _, vks2, tokens2 = windows_tools.canonicalize_keyboard_arguments({"text": "win a prize ... r"})
        chord2 = windows_tools.detect_blocked_system_chords(vks2, tokens2)
        self.assertIsNone(chord2, f"Prose text must not trip Win+R, got: {chord2}")

        # 3. modifiers=['win'], key='r' must be caught as Win+R
        _, _, vks3, tokens3 = windows_tools.canonicalize_keyboard_arguments({"modifiers": ["win"], "key": "r"})
        chord3 = windows_tools.detect_blocked_system_chords(vks3, tokens3)
        self.assertEqual(chord3, "Win+R", "modifiers=['win'], key='r' must be detected as Win+R")

        # 4. Alt+Tab must be detected via atomic token without Win fallback
        _, _, vks4, tokens4 = windows_tools.canonicalize_keyboard_arguments({"hotkey": "alt+tab"})
        chord4 = windows_tools.detect_blocked_system_chords(vks4, tokens4)
        self.assertEqual(chord4, "Alt+Tab", "alt+tab must be detected as Alt+Tab")

    def test_4_recovery_token_single_use_unlink_failure_fails_closed(self):
        """Directive 4: consume_admin_recovery_token strictly fails closed if os.remove fails."""
        import hashlib
        tok = "admin_recovery_pass_12345"
        tok_hash = hashlib.sha256(tok.encode('utf-8')).hexdigest()

        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps({
                 "token_hash": tok_hash,
                 "expires_at": time.time() + 300
             }))), \
             patch("os.remove", side_effect=OSError("Access denied during unlink")):
            # Token matches hash, but unlink fails: MUST return False to prevent multi-use!
            success_valid = phone_approval_portal.consume_admin_recovery_token(tok)
            self.assertFalse(success_valid, "Must fail closed if unlinking token file fails!")

    def test_5_compiled_in_safety_floor_covers_all_consequential_and_fact_tools(self):
        """Directive 5: COMPILED_IN_CONSEQUENTIAL_TOOLS contains all OS consequential tools and cannot be weakened by disk config."""
        cfg = rails_config.RailsConfig()

        # Consequential tools must be protected
        self.assertTrue(cfg.is_confirmation_required("homie_set_clipboard"))
        self.assertTrue(cfg.is_confirmation_required("homie_launch_app"))
        self.assertTrue(cfg.is_confirmation_required("launch_app"))  # alias check

        # Simulating a hostile disk edit that empties require_confirmation in JSON
        with patch.object(cfg, "_cached_config", {"safety": {"require_confirmation": []}}):
            self.assertTrue(cfg.is_confirmation_required("homie_set_clipboard"))
            self.assertTrue(cfg.is_confirmation_required("homie_launch_app"))
            self.assertTrue(cfg.is_confirmation_required("launch_app"))

    def test_6_human_confirmation_rejects_worker_and_agent_callers(self):
        """Directive 6: ConfirmationGate.confirm() rejects worker and agent callers and requires verified presence."""
        with patch("device_registry.get_enrolled_devices", return_value={}):
            gate = rails_confirmation.ConfirmationGate()
            req = gate.create_request("homie_set_clipboard", {"text": "secret"})

            # Worker caller must be denied
            ok1, msg1, tok1 = gate.confirm(req.request_id, human_caller_id="worker_compromised")
            self.assertFalse(ok1)
            self.assertIsNone(tok1)
            self.assertIn("verified human operator", msg1)

            # Agent caller must be denied
            ok2, msg2, tok2 = gate.confirm(req.request_id, human_caller_id="agent_loop")
            self.assertFalse(ok2)
            self.assertIsNone(tok2)

            # Missing presence gesture when no device is enrolled is denied
            ok_none, msg_none, _ = gate.confirm(req.request_id)
            self.assertFalse(ok_none)
            self.assertIn("presence", msg_none.lower())

            # Invalid presence gesture is denied
            ok_bad, msg_bad, _ = gate.confirm(req.request_id, presence_gesture="wrong_gesture")
            self.assertFalse(ok_bad)
            self.assertIn("invalid", msg_bad.lower())

            # Verified presence gesture matching ephemeral challenge is accepted
            ok3, msg3, tok3 = gate.confirm(req.request_id, presence_gesture=req.presence_challenge)
            self.assertTrue(ok3)
            self.assertIsNotNone(tok3)


if __name__ == "__main__":
    unittest.main()
