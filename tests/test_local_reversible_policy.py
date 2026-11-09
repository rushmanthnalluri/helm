"""Keep the desktop fast path useful without weakening taint gates for agents."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import taint_tracker


class TestLocalReversiblePolicy(unittest.TestCase):
    def setUp(self):
        taint_tracker.clear_all_taints()
        taint_tracker.mark_session_tainted("screen_reader", source="screen_capture")

    def tearDown(self):
        taint_tracker.clear_all_taints()

    def test_local_user_can_request_allowlisted_reversible_desktop_action(self):
        for caller in ("desktop_user", "desktop_voice"):
            allowed, needs_step_up, _ = taint_tracker.check_action_privilege(
                caller, "REVERSIBLE", "homie_play_youtube", {"query": "Telugu songs"}
            )
            self.assertTrue(allowed)
            self.assertFalse(needs_step_up)

    def test_unknown_or_nonlocal_actions_still_need_step_up(self):
        cases = (
            ("desktop_user", "REVERSIBLE", "arbitrary_action"),
            ("ai_text_agent", "REVERSIBLE", "homie_play_youtube"),
            ("desktop_user", "WRITE_EXEC", "homie_set_clipboard"),
        )
        for caller, tier, tool in cases:
            with self.subTest(caller=caller, tier=tier, tool=tool):
                allowed, needs_step_up, reason = taint_tracker.check_action_privilege(
                    caller, tier, tool, {}
                )
                self.assertFalse(allowed)
                self.assertTrue(needs_step_up)
                self.assertIn("STEP_UP_REQUIRED", reason)


if __name__ == "__main__":
    unittest.main()
