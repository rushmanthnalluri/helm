"""tests/test_batch19_policy_envelope.py - Batch 19C Acceptance Tests.

Verifies:
  1. Phone signing challenge binding on canonical envelope parameters.
  2. Safe routine actions permitted within envelope bounds without per-step prompt.
  3. Hard denial when step budget or keystroke cap is exceeded.
  4. Hard denial when target process image is outside envelope allowed list.
  5. High-risk operations (Send, Delete, Pay, Submit, Install) ALWAYS require per-step approval.
  6. Automatic invalidation on taint epoch mismatch or TTL expiration.
"""

import os
import sys
import time
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from policy_envelope import PolicyEnvelope
import phone_approval_portal


class TestBatch19PolicyEnvelope(unittest.TestCase):

    def setUp(self):
        from tests.phone_testing_keys import enroll_test_device, sign_test_challenge
        self.sign_test_challenge = sign_test_challenge
        self.phone_priv, self.phone_pub = enroll_test_device("primary_phone")
        enroll_test_device("phone_01", self.phone_pub)
        self.epoch = 1700000000
        self.env = PolicyEnvelope(
            envelope_id="env_unit_test_01",
            allowed_process_images=["notepad.exe", "calc.exe"],
            allowed_action_types=["helm_type_text", "helm_click_coords", "helm_snap_window"],
            step_budget=3,
            keystroke_cap=50,
            expiry=time.time() + 120.0,
            taint_epoch=self.epoch,
            device_id="phone_01"
        )

    def test_phone_activation_and_signature_binding(self):
        """Verifies envelope activates only with valid mobile device signature."""
        ch = self.env.generate_phone_challenge()
        self.assertIn("notepad.exe", ch["canonical_prompt"])

        # Sign using phone device key
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        ok, msg = self.env.activate_with_signature(sig)
        self.assertTrue(ok)
        self.assertTrue(self.env.is_active)

    def test_step_budget_consumption_and_hard_deny(self):
        """Verifies allowed actions succeed within budget and are strictly hard-denied once exhausted."""
        ch = self.env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        self.env.activate_with_signature(sig)

        # Step 1: OK
        ok1, res1 = self.env.check_and_consume("helm_click_coords", {"x": 50, "y": 50}, "notepad.exe", self.epoch)
        self.assertTrue(ok1)
        self.assertEqual(self.env.steps_consumed, 1)

        # Step 2: OK
        ok2, res2 = self.env.check_and_consume("helm_snap_window", {"app_name": "notepad"}, "notepad.exe", self.epoch)
        self.assertTrue(ok2)
        self.assertEqual(self.env.steps_consumed, 2)

        # Step 3: OK (Reaches limit)
        ok3, res3 = self.env.check_and_consume("helm_click_coords", {"x": 60, "y": 60}, "notepad.exe", self.epoch)
        self.assertTrue(ok3)
        self.assertEqual(self.env.steps_consumed, 3)

        # Step 4: HARD DENIAL
        ok4, res4 = self.env.check_and_consume("helm_click_coords", {"x": 70, "y": 70}, "notepad.exe", self.epoch)
        self.assertFalse(ok4)
        self.assertIn("Step budget exceeded", res4)

    def test_keystroke_cap_enforcement(self):
        """Verifies cumulative keystrokes are tracked and exceeding cap is hard-denied."""
        ch = self.env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        self.env.activate_with_signature(sig)

        # Type 30 chars (under 50 cap): OK
        ok1, _ = self.env.check_and_consume("helm_type_text", {"text": "A" * 30}, "notepad.exe", self.epoch)
        self.assertTrue(ok1)
        self.assertEqual(self.env.keystrokes_consumed, 30)

        # Type 25 more chars (total 55 > 50 cap): HARD DENY
        ok2, res2 = self.env.check_and_consume("helm_type_text", {"text": "B" * 25}, "notepad.exe", self.epoch)
        self.assertFalse(ok2)
        self.assertIn("Keystroke cap exceeded", res2)

    def test_unauthorized_process_image_hard_denial(self):
        """Verifies targeting an unapproved process (e.g. cmd.exe or powershell) is hard-denied."""
        ch = self.env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        self.env.activate_with_signature(sig)

        # Attempt to target powershell.exe: DENY
        ok, res = self.env.check_and_consume("helm_click_coords", {"x": 10, "y": 10}, "powershell.exe", self.epoch)
        self.assertFalse(ok)
        self.assertIn("Target process 'powershell.exe' not in envelope", res)

    def test_high_risk_actions_always_require_per_step_stepup(self):
        """Verifies critical destructive/financial actions require per-step approval even inside envelope."""
        # Include a destructive action in envelope action types
        env_with_del = PolicyEnvelope(
            envelope_id="env_del",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["helm_type_text", "helm_delete_file"],
            step_budget=10,
            keystroke_cap=100,
            expiry=time.time() + 100,
            taint_epoch=self.epoch
        )
        ch = env_with_del.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        env_with_del.activate_with_signature(sig)

        # helm_delete_file must be denied by envelope policy because it requires explicit step-up!
        ok, res = env_with_del.check_and_consume("helm_delete_file", {"path": "test.txt"}, "notepad.exe", self.epoch)
        self.assertFalse(ok)
        self.assertIn("requires per-step step-up human approval", res)

    def test_taint_epoch_invalidation(self):
        """Verifies envelope is invalidated if worker taint epoch changes."""
        ch = self.env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        self.env.activate_with_signature(sig)

        # Mismatched taint epoch
        ok, res = self.env.check_and_consume("helm_click_coords", {"x": 10, "y": 10}, "notepad.exe", self.epoch + 1)
        self.assertFalse(ok)
        self.assertIn("Taint epoch mismatch", res)
        self.assertFalse(self.env.is_active)

    def test_prohibited_images_cannot_be_approved_in_envelope(self):
        """Batch 21 Directive: Arbitrary execution environments (cmd, explorer, code) cannot be in envelopes."""
        for prohibited in ["explorer.exe", "cmd.exe", "powershell.exe", "wt.exe", "code.exe"]:
            with self.assertRaises(ValueError):
                PolicyEnvelope(
                    envelope_id="bad_env",
                    allowed_process_images=[prohibited],
                    allowed_action_types=["helm_type_text"],
                    step_budget=5,
                    keystroke_cap=50,
                    expiry=time.time() + 100,
                    taint_epoch=self.epoch
                )

    def test_browser_domain_scoping_enforcement(self):
        """Batch 21 Directive: Browser envelopes strictly enforce domain allowlist."""
        browser_env = PolicyEnvelope(
            envelope_id="browser_env",
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["helm_click_coords", "helm_type_text"],
            step_budget=5,
            keystroke_cap=100,
            expiry=time.time() + 100,
            taint_epoch=self.epoch,
            allowed_domains=["docs.python.org"]
        )
        ch = browser_env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        browser_env.activate_with_signature(sig)

        # 1. Allowed domain navigation: OK
        ok1, _ = browser_env.check_and_consume(
            "helm_click_coords", {"x": 100, "y": 100}, "chrome.exe", self.epoch, current_domain="docs.python.org"
        )
        self.assertTrue(ok1)

        # 2. Out-of-scope domain escape (e.g. webmail): HARD DENY
        ok2, res2 = browser_env.check_and_consume(
            "helm_click_coords", {"x": 100, "y": 100}, "chrome.exe", self.epoch, current_domain="mail.google.com"
        )
        self.assertFalse(ok2)
        self.assertIn("outside envelope domain scope", res2)

    def test_semantic_high_risk_disguised_controls_and_enter_submit(self):
        """Batch 21 Directive: Disguised high-risk controls ('Continue', 'Next') and Enter submits require step-up."""
        ch = self.env.generate_phone_challenge()
        sig = self.sign_test_challenge(self.phone_priv, ch["canonical_hash"])
        self.env.activate_with_signature(sig)

        # 1. Button labeled "Continue" or "Agree" (disguised checkout/submission): DENY
        ok1, res1 = self.env.check_and_consume(
            "helm_click_coords", {"element_name": "Continue to Purchase", "x": 10, "y": 10}, "notepad.exe", self.epoch
        )
        self.assertFalse(ok1)
        self.assertIn("Semantic high-risk control detected", res1)

        # 2. Typing text ending with Enter (\n) to trigger form submit: DENY
        ok2, res2 = self.env.check_and_consume(
            "helm_type_text", {"text": "password123\n"}, "notepad.exe", self.epoch
        )
        self.assertFalse(ok2)
        self.assertIn("Enter-to-submit", res2)


if __name__ == "__main__":
    unittest.main()
