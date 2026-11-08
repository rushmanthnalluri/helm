"""Unit and security tests for Batch 11 features:
- Multi-step indirect injection attack mitigation via Taint Tracking (taint_tracker.py)
- Out-of-band step-up approval gate for tainted sessions
- Desktop grounding engine with safety limits, step budgets, and dry-run (desktop_agent.py)
- Workflow compiler & deterministic macro orchestration (workflow_compiler.py)
- Fast command routing in homie.py
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import taint_tracker
import desktop_agent
import workflow_compiler
import homie_mcp
import homie

class TestBatch11Features(unittest.TestCase):
    def setUp(self):
        taint_tracker.clear_all_taints()
        desktop_agent.reset_abort()

    def tearDown(self):
        taint_tracker.clear_all_taints()
        desktop_agent.reset_abort()

    def test_multi_step_injection_attack_intercepted_by_taint(self):
        """Simulates an indirect injection multi-step attack and verifies taint gate interception."""
        session_id = "test_attacker_session"

        # Seed untrusted screen memory containing prompt injection
        import semantic_screen_memory
        semantic_screen_memory.record_screen_event("chrome.exe", "Invoice #1042 - Google Chrome", "Pay to account 12345")

        # Step 1: Attacker agent reads untrusted screen memory containing prompt injection
        out1 = homie_mcp.execute_mcp_tool("homie_read_screen_memory", {"query": "Invoice"}, caller_id=session_id)
        self.assertIn("[UNTRUSTED_DATA_NONCE_", out1)

        # Step 2: Verify session is now marked TAINTED
        self.assertTrue(taint_tracker.is_session_tainted(session_id))

        # Step 3: Attacker attempts to execute a WRITE_EXEC action (e.g. set clipboard or launch app)
        out2 = homie_mcp.execute_mcp_tool("homie_set_clipboard", {"text": "exfiltrated_data"}, caller_id=session_id)
        
        # Step 4: Verify WRITE action was INTERCEPTED and blocked for step-up approval
        self.assertIn("Security Gate", out2)
        self.assertIn("STEP_UP_REQUIRED", out2)

        # Step 5: Test step-up approval
        # Extract step-up ID
        import re
        match = re.search(r'\[ID:\s*([a-f0-9]+)\]', out2)
        self.assertIsNotNone(match)
        step_up_id = match.group(1)

        ok_approve, item, msg = taint_tracker.approve_step_up(step_up_id)
        self.assertTrue(ok_approve)
        self.assertEqual(item["tool_name"], "homie_set_clipboard")

    def test_desktop_grounding_safety_and_dry_run(self):
        """Tests desktop agent dry run mode, step budget, and emergency abort."""
        engine = desktop_agent.DesktopGroundingEngine(target_window_title="NonExistentWindow", max_steps=3, dry_run=True)
        ok, msg = engine.attach_target_window()
        self.assertFalse(ok)

        # Test step budget limit
        engine2 = desktop_agent.DesktopGroundingEngine(max_steps=2, dry_run=True)
        engine2.steps_taken = 2
        ok_step, msg_step = engine2.click_element("SomeButton")
        self.assertFalse(ok_step)
        self.assertIn("budget exceeded", msg_step.lower())

        # Test emergency abort
        desktop_agent.request_abort()
        self.assertTrue(desktop_agent.is_abort_requested())
        ok_abort, msg_abort = engine2.click_element("SomeButton")
        self.assertFalse(ok_abort)
        self.assertIn("aborted", msg_abort.lower())

    def test_workflow_compiler_and_macro_replay(self):
        """Tests compiling recorded agent steps into deterministic fast macros."""
        steps = [
            {"action": "click", "element": {"name": "FileMenu", "type": "MenuItem"}},
            {"action": "type", "element": {"name": "SearchBox", "type": "EditControl"}, "text": "search {query}"}
        ]

        ok, msg = workflow_compiler.compile_agent_steps_to_macro("test_workflow_alpha", steps)
        self.assertTrue(ok)
        self.assertIn("successfully compiled", msg)

        # Replay plan in dry-run
        ok_replay, msg_replay = workflow_compiler.replay_compiled_macro(
            "test_workflow_alpha",
            params={"query": "python_automation"},
            dry_run=True
        )
        self.assertTrue(ok_replay)
        self.assertIn("DRY-RUN", msg_replay)
        self.assertIn("search python_automation", msg_replay)

    def test_fast_commands_batch11(self):
        """Verifies fast command routing for taint status and emergency stop."""
        handled, msg = homie.try_fast_command("taint status")
        self.assertTrue(handled)
        self.assertIn("Taint Security Gate", msg)

        handled2, msg2 = homie.try_fast_command("emergency stop")
        self.assertTrue(handled2)
        self.assertIn("emergency abort", msg2.lower())

if __name__ == '__main__':
    unittest.main()
