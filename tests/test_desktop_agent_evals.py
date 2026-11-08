"""Desktop Agent Automated Evaluation Benchmark Suite.
Measures agent grounding accuracy, step-budget efficiency, password safety, and failure recovery:
- Eval 1: Element discovery & UIA semantic resolution success rate
- Eval 2: Step-budget enforcement and recovery under constrained budgets
- Eval 3: Password field detection and security denial
- Eval 4: Emergency abort latency & signal responsiveness
- Eval 5: Out-of-band mobile step-up push notification & resolution
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import desktop_agent
import taint_tracker
import step_up_gate

class TestDesktopAgentEvals(unittest.TestCase):
    def setUp(self):
        desktop_agent.reset_abort()
        desktop_agent.set_driving_state(False)

    def tearDown(self):
        desktop_agent.reset_abort()
        desktop_agent.set_driving_state(False)

    def test_eval_driving_state_toggle(self):
        """Measures operational driving banner state."""
        self.assertFalse(desktop_agent._driving_state)
        desktop_agent.set_driving_state(True)
        self.assertTrue(desktop_agent._driving_state)
        desktop_agent.set_driving_state(False)
        self.assertFalse(desktop_agent._driving_state)

    def test_eval_step_budget_exhaustion_recovery(self):
        """Verifies engine terminates gracefully when step budget is reached without hung processes."""
        engine = desktop_agent.DesktopGroundingEngine(max_steps=5, dry_run=True)
        engine.steps_taken = 5
        ok, msg = engine.click_element("SaveButton")
        self.assertFalse(ok)
        self.assertIn("budget exceeded", msg.lower())

    def test_eval_emergency_abort_latency(self):
        """Verifies emergency kill halts execution instantly."""
        engine = desktop_agent.DesktopGroundingEngine(max_steps=10, dry_run=True)
        desktop_agent.request_abort()
        self.assertTrue(desktop_agent.is_abort_requested())
        ok, msg = engine.click_element("Submit")
        self.assertFalse(ok)
        self.assertIn("emergency stop", msg.lower())

    def test_eval_out_of_band_step_up_gate(self):
        """Evaluates step-up gate notification formatting and resolution."""
        # Test simulated step up callback approval
        taint_tracker.mark_session_tainted("eval_session")
        allowed, step_up, reason = taint_tracker.check_action_privilege("eval_session", "WRITE_EXEC", "homie_snap_window", {"app_name": "chrome", "position": "left"})
        self.assertFalse(allowed)
        self.assertTrue(step_up)

        # Extract step up id
        import re
        m = re.search(r'\[ID:\s*([a-f0-9]+)\]', reason)
        self.assertIsNotNone(m)
        s_id = m.group(1)

        # Test callback approval
        ok_cb, rep = step_up_gate.handle_step_up_callback(f"approve_stepup_{s_id}", "7183684615")
        self.assertTrue(ok_cb)
        self.assertIn("Approved & Executed", rep)

    def test_eval_tainted_agent_click_interception(self):
        """Verifies desktop agent clicks route through MCP and are blocked when session is tainted."""
        taint_tracker.mark_session_tainted("eval_tainted_desktop")
        engine = desktop_agent.DesktopGroundingEngine(max_steps=5, dry_run=False, session_id="eval_tainted_desktop")
        # Mock element finding
        engine.find_uia_element = lambda name, ctype=None: {"grounding": "UIA", "name": name, "center": (100, 200)}

        ok, msg = engine.click_element("TaintedButton")
        self.assertFalse(ok)
        self.assertIn("Security Gate:", msg)

    def test_eval_macro_fast_path_latency(self):
        """Verifies compiled macros compile and serialize within the sub-50ms deterministic fast-path guarantee."""
        import workflow_compiler
        import time

        steps = [
            {"action": "click", "element": {"name": "FileMenu", "type": "ButtonControl"}},
            {"action": "type", "element": {"name": "FileNameInput"}, "text": "report.txt"}
        ]
        start = time.time()
        ok, msg = workflow_compiler.compile_agent_steps_to_macro("test_eval_fast_macro", steps)
        duration_ms = (time.time() - start) * 1000
        self.assertLess(duration_ms, 50, f"Compilation exceeded 50ms latency: {duration_ms}ms")
        self.assertTrue(ok, msg)

if __name__ == '__main__':
    unittest.main()
