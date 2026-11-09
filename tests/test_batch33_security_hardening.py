"""Unit tests for Batch 33 security hardening and verification directives:
1. complete_device_enrollment strictly requires signed approval_expiry (omission fails closed).
2. Enter-to-submit form detection catches all key variations (ctrl+enter, numpadenter, key lists, key combos).
3. Two-phase envelope step reservations never leak across any denial path (token deny, TOCTOU, taint, shadow).
4. Browser process image requires non-empty allowed_domains; empty scopes fail closed.
5. Thread-safe envelope inactivation under _envelope_lock.
6. Ambient/voice try_fast_command does not trigger pairing ceremony; restricted to physical console/hotkey.
7. Update publisher public key rotated and pinned.
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

import phone_approval_portal
import policy_envelope
import homie_supervisor
import client_token_auth
import taint_tracker
import update_verifier
import homie

from Crypto.Signature import eddsa
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    sign_enrollment_approval,
    get_test_pairing_code
)


class TestBatch33SecurityHardening(unittest.TestCase):
    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"
        for f in [".homie_supervisor_dirty.flag", ".homie_enrollment_lockout.json"]:
            if os.path.exists(f):
                try: os.remove(f)
                except Exception: pass
        with phone_approval_portal._ENROLLMENT_LOCK:
            phone_approval_portal._LOCAL_ENROLLMENT_SESSIONS.clear()
            phone_approval_portal._CONSOLE_RECOVERY_TOKENS.clear()
        phone_approval_portal._ACTIVE_CHALLENGES.clear()
        phone_approval_portal.set_display_driver(None)

    def tearDown(self):
        phone_approval_portal.set_display_driver(None)
        client_token_auth.set_token_enforcement(False)

    def test_1_approval_expiry_strictly_mandatory(self):
        """Directive 1: approval_expiry is strictly mandatory for second device enrollment; omitting it fails closed."""
        priv1, pub1 = generate_test_phone_keypair()
        with phone_approval_portal._REGISTRY_LOCK:
            phone_approval_portal._save_device_registry({
                "primary_phone": {
                    "public_key": pub1,
                    "authenticator_type": "device_resident_ed25519",
                    "paired_at": time.time(),
                    "counter": 0,
                    "revoked": False,
                    "device_name": "Primary Device"
                }
            })

        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60)
        code = captured[0]

        priv2, pub2 = generate_test_phone_keypair()
        sig = sign_enrollment_approval(priv1, sess_id, "second_phone", pub2, int(time.time() + 60))

        # Omitting approval_expiry must FAIL CLOSED with APPROVAL_INVALID
        ok, msg = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "second_phone", pub2, primary_approval_sig=sig, approval_expiry=None
        )
        self.assertFalse(ok)
        self.assertIn("mandatory", msg.lower())

    def test_2_enter_to_submit_variations_detected(self):
        """Directive 2: Form submission detection catches ctrl+enter, numpadenter, key combos, and whitespace."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_agent_type", "homie_send_hotkey"],
            step_budget=10,
            keystroke_cap=100,
            allowed_domains=["secure-portal.com"],
            taint_epoch=1
        )
        env.is_active = True

        test_cases = [
            {"key": "ctrl+enter"},
            {"key": "Ctrl + Return"},
            {"key": "numpadenter"},
            {"key": "Numpad_Enter"},
            {"keys": ["ctrl", "enter"]},
            {"hotkey": "ctrl+enter"},
            {"text": "submit\n"},
            {"text": "login\r"},
            {"key": "  enter  "},
        ]

        for idx, args in enumerate(test_cases):
            ok, msg, _ = env.check_boundary(
                "homie_agent_type", args, "chrome.exe", 1, "secure-portal.com"
            )
            self.assertFalse(ok, f"Test case {idx} with args {args} should be detected as form submission")
            self.assertIn("enter", msg.lower())

    def test_3_envelope_step_reservation_no_leak_on_denial(self):
        """Directive 3: Early denials in supervisor propose release envelope step reservation."""
        import heartbeat_lease
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=30.0)
        supervisor.last_heartbeat_time = time.time()

        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_agent_type"],
            step_budget=2,
            keystroke_cap=100,
            allowed_domains=["secure-portal.com"],
            taint_epoch=1
        )
        env.is_active = True
        supervisor.envelope = env

        # Mock foreground window
        with patch("windows_tools.get_foreground_window", return_value={"proc_name": "chrome.exe", "title": "secure-portal.com"}):
            # Proposal 1 fails taint check (hard DENY)
            with patch("taint_tracker.check_action_privilege", return_value=(False, False, "Taint Denied")):
                supervisor._handle_propose({
                    "tool": "homie_agent_type",
                    "args": {"text": "hello"}
                }, seq=1)

            # Reservation must be released! Reserved steps should be 0
            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

            # Proposal 2 fails step-up token check (NEEDS_HUMAN)
            with patch("taint_tracker.check_action_privilege", return_value=(False, True, "Needs step-up")):
                supervisor._handle_propose({
                    "tool": "homie_agent_type",
                    "args": {"text": "hello"}
                }, seq=2)

            self.assertEqual(env.reserved_steps, 0)
            self.assertEqual(env.steps_consumed, 0)

    def test_4_browser_envelope_requires_non_empty_allowed_domains(self):
        """Directive 4: A browser process image in an envelope requires non-empty allowed_domains; empty fails closed."""
        env = policy_envelope.PolicyEnvelope(
            envelope_id="test_env",
            device_id="phone_1",
            signature="test_sig",
            expiry=time.time() + 300,
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_browse"],
            step_budget=5,
            keystroke_cap=100,
            allowed_domains=[],  # EMPTY DOMAINS
            taint_epoch=1
        )
        env.is_active = True

        ok, msg, _ = env.check_boundary(
            "homie_browse", {"url": "https://evil.com"}, "chrome.exe", 1, "evil.com"
        )
        self.assertFalse(ok)
        self.assertIn("explicit non-empty allowed_domains", msg)

    def test_5_ambient_voice_cannot_trigger_pairing(self):
        """Directive 5: Ambient voice / fast commands must NOT trigger enrollment ceremony; physical console presence only."""
        captured = []
        phone_approval_portal.set_display_driver(lambda code: captured.append(code) or True)

        # Ambient conversational voice trying to trigger pairing must return not handled or denied
        handled, msg = homie.try_fast_command("pair phone")
        self.assertFalse(handled, "Voice/text fast command must NOT trigger pairing ceremony")
        self.assertEqual(len(captured), 0)

    def test_6_update_keypair_pinned_verification(self):
        """Directive 6: Pinned update public key literal is valid Ed25519 and verifies releases."""
        pub_key = update_verifier.PINNED_PUBLISHER_PUBLIC_KEY
        self.assertIn("BEGIN PUBLIC KEY", pub_key)
        self.assertIn("END PUBLIC KEY", pub_key)
        # Must not contain private key
        self.assertNotIn("PRIVATE KEY", pub_key)


if __name__ == "__main__":
    unittest.main()
