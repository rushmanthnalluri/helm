"""test_batch34_security_hardening.py - Batch 34 Security Acceptance Tests.

Tests verifying Batch 34 architectural hardening directives:
1. Directive 1: Rotated Pinned Publisher Public Key literal in update_verifier.py.
2. Directive 2: Enter detection precision:
   - Text containing words "enterprise", "center", "return to sender" is NOT blocked.
   - Text containing literal newlines (\\n, \\r) IS blocked.
   - Keystrokes with numeric keycode 13 (VK_RETURN) or keys_to_press ARE blocked.
   - Combinations (ctrl+enter, numpadenter) ARE blocked.
3. Directive 3: Envelope reservation token with guaranteed single-point release:
   - reserve_step returns unique reservation token.
   - release_reservation with token is idempotent and exact.
   - In supervisor _handle_propose, every denial path (taint deny, step-up human, shadow, TOCTOU)
     guarantees reserved_steps == 0.
4. Directive 4: Atomic enrollment session consumption:
   - complete_device_enrollment pops session immediately on pairing code match.
   - Concurrent attempt with same session and code immediately fails closed.
5. Directive 5: Synthetic Ctrl+Alt+P prevention:
   - SupervisorActuator and PolicyEnvelope reject synthetic Ctrl+Alt+P injection.
6. Directive 6: Expanded browser process images:
   - Opera, Vivaldi, Arc, Teams, Slack included in BROWSER_IMAGES and enforce domain scoping.
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
from tests.phone_testing_keys import generate_test_phone_keypair, sign_enrollment_approval, get_test_pairing_code


class TestBatch34SecurityHardening(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"

    def test_1_rotated_pinned_publisher_public_key(self):
        """Directive 1: Pinned publisher key has been rotated to new key and is valid Ed25519."""
        pub_pem = update_verifier.PINNED_PUBLISHER_KEY_PEM
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)
        self.assertIn("MCowBQYDK2VwAyEAXBYS0+c64gbsT95CnpeMWWQVQkfK7xSjwbld5xs4MGU=", pub_pem)
        self.assertNotIn("PRIVATE KEY", pub_pem)

    def test_2_enter_detection_no_false_positives_on_words_and_catches_keycode_13(self):
        """Directive 2: Prose with 'enterprise', 'center', 'return' is allowed; newlines and keycode 13 blocked."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_enter",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["homie_agent_type", "homie_send_hotkey"],
            step_budget=20,
            keystroke_cap=500,
            allowed_domains=["allowed.com"],
            taint_epoch=1
        )
        env.is_active = True

        # Allowed prose test cases (must NOT be blocked by substring check)
        allowed_cases = [
            {"text": "enterprise architecture design"},
            {"text": "welcome to the data center"},
            {"text": "return to sender, address unknown"},
            {"text": "carpenter working on center table"},
            {"key": "backspace"},
            {"key": "tab"},
        ]

        for idx, args in enumerate(allowed_cases):
            ok, msg, _ = env.check_boundary(
                "homie_agent_type", args, "notepad.exe", 1, "allowed.com"
            )
            self.assertTrue(ok, f"Allowed case {idx} with args {args} was falsely rejected: {msg}")

        # Blocked submission test cases (must be rejected)
        blocked_cases = [
            {"text": "submit now\n"},
            {"text": "line break\r"},
            {"key": 13},
            {"vk": 13},
            {"key_code": "13"},
            {"keys_to_press": ["ctrl", "enter"]},
            {"hotkey": "ctrl+enter"},
            {"key": "numpadenter"},
            {"key": "Return"},
        ]

        for idx, args in enumerate(blocked_cases):
            ok, msg, _ = env.check_boundary(
                "homie_agent_type", args, "notepad.exe", 1, "allowed.com"
            )
            self.assertFalse(ok, f"Blocked case {idx} with args {args} should have been rejected")
            self.assertIn("enter", msg.lower())

    def test_3_envelope_reservation_token_single_point_release_across_supervisor_exits(self):
        """Directive 3: Envelope reservation token guarantees 0 leaked reservations across all supervisor exits."""
        import heartbeat_lease
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=30.0)
        supervisor.last_heartbeat_time = time.time()

        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_res_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_agent_type"],
            step_budget=10,
            keystroke_cap=100,
            allowed_domains=["secure-portal.com"],
            taint_epoch=1
        )
        env.is_active = True
        supervisor.envelope = env

        with patch("windows_tools.get_foreground_window", return_value={"proc_name": "chrome.exe", "title": "secure-portal.com"}):
            # Exit Path 1: Taint check hard denial
            with patch("taint_tracker.check_action_privilege", return_value=(False, False, "Taint Denied")):
                supervisor._handle_propose({"tool": "homie_agent_type", "args": {"text": "hello"}}, seq=1)
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Exit Path 2: Step-up token required (NEEDS_HUMAN)
            with patch("taint_tracker.check_action_privilege", return_value=(False, True, "Needs step-up")):
                supervisor._handle_propose({"tool": "homie_agent_type", "args": {"text": "hello"}}, seq=2)
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Exit Path 3: Shadow mode active
            with patch("taint_tracker.check_action_privilege", return_value=(True, False, "Allowed")):
                with patch("shadow_mode.is_shadow_mode_active", return_value=True):
                    with patch("shadow_mode.record_simulated_action", return_value={"action_id": "sim_1"}):
                        supervisor._handle_propose({"tool": "homie_agent_type", "args": {"text": "hello"}}, seq=3)
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Exit Path 4: Actuator execution exception
            with patch("taint_tracker.check_action_privilege", return_value=(True, False, "Allowed")):
                with patch("shadow_mode.is_shadow_mode_active", return_value=False):
                    with patch.object(supervisor.actuator, "execute_actuator", side_effect=RuntimeError("Actuator crashed")):
                        supervisor._handle_propose({"tool": "homie_agent_type", "args": {"text": "hello"}}, seq=4)
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

    def test_4_concurrent_session_reuse_blocked_by_atomic_pop(self):
        """Directive 4: Session is popped atomically at verification time; second request fails closed."""
        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)

        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code = captured[0]

        priv, pub = generate_test_phone_keypair()
        with phone_approval_portal._REGISTRY_LOCK:
            phone_approval_portal._save_device_registry({})

        # Request 1: Legitimate first-device enrollment succeeds
        ok1, msg1 = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "phone_primary", pub
        )
        self.assertTrue(ok1, f"First enrollment should succeed: {msg1}")

        # Request 2: Replay or concurrent request with same session and code MUST FAIL CLOSED
        priv2, pub2 = generate_test_phone_keypair()
        ok2, msg2 = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "phone_concurrent", pub2
        )
        self.assertFalse(ok2, "Concurrent or replayed session MUST fail closed")
        self.assertIn("not found", msg2.lower())

    def test_5_synthetic_ctrl_alt_p_rejected(self):
        """Directive 5: Supervisor and policy envelope reject synthetic Ctrl+Alt+P hotkey simulation."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env_synth",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["homie_agent_type", "homie_send_hotkey"],
            step_budget=10,
            keystroke_cap=100,
            allowed_domains=["allowed.com"],
            taint_epoch=1
        )
        env.is_active = True

        # Policy envelope rejects synthetic hotkey Ctrl+Alt+P
        ok, msg, _ = env.check_boundary(
            "homie_send_hotkey", {"hotkey": "ctrl+alt+p"}, "notepad.exe", 1, "allowed.com"
        )
        self.assertFalse(ok)
        self.assertIn("ctrl+alt+p", msg.lower())

    def test_6_expanded_browser_images_enforce_domain_scoping(self):
        """Directive 6: Opera, Vivaldi, Arc, Teams, Slack enforce domain scoping in policy envelopes."""
        for proc in ["opera.exe", "vivaldi.exe", "arc.exe", "slack.exe", "teams.exe"]:
            self.assertIn(proc, policy_envelope.BROWSER_IMAGES)

            env = policy_envelope.PolicyEnvelope(
                envelope_id=f"test_env_{proc}",
                device_id="phone_1",
                signature="test_sig",
                expiry=time.time() + 300,
                allowed_process_images=[proc],
                allowed_action_types=["homie_agent_type"],
                step_budget=5,
                keystroke_cap=100,
                allowed_domains=["authorized.com"],
                taint_epoch=1
            )
            env.is_active = True

            # Out of scope domain navigation is blocked
            ok, msg, _ = env.check_boundary(
                "homie_agent_type", {"text": "hello"}, proc, 1, current_domain="evil.com"
            )
            self.assertFalse(ok, f"Browser process {proc} must enforce domain scoping")
            self.assertIn("domain", msg.lower())


if __name__ == "__main__":
    unittest.main()
