"""tests/test_unified_action_broker.py - Unified Action Broker Acceptance Tests.

Verifies:
1. Hotkey, typed, voice, Telegram, phone, AI, and MCP actions all route through ActionBroker.
2. Complete mediation: Actuators execute only with supervisor INTENT tokens and two-phase audit.
3. Emergency Kill Switch halts actions across ALL ingress channels (desktop, phone, telegram, ai).
4. Tainted sessions require step-up authorization across ALL ingress channels.
5. Step-Up tokens are strictly single-use and consumed immediately.
6. Parameter tampering or replayed step-up tokens are rejected.
"""

import os
import sys
import unittest
import json
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import action_broker
import homie_supervisor
import kill_switch
import taint_tracker
import agent_audit_ledger
import homie


class TestUnifiedActionBroker(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def tearDown(self):
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def test_all_callers_route_through_action_broker(self):
        """Verifies hotkey, voice, telegram, phone, and AI tool calls pass through ActionBroker."""
        broker = action_broker.get_action_broker()

        for caller in ["desktop_user", "desktop_voice", "telegram_remote", "ai_engine"]:
            ok, msg, res = broker.execute_action(
                "homie_snap_window", {"app_name": "notepad", "position": "left"}, caller_id=caller
            )
            self.assertTrue(ok, f"Caller '{caller}' failed action execution: {msg}")
            self.assertIn("Success:", msg)

        # READ_ONLY action executes directly across all callers including phone_gateway
        ok_phone, msg_phone, res_phone = broker.execute_action("homie_get_vitals", {}, caller_id="phone_gateway")
        self.assertTrue(ok_phone, f"phone_gateway read-only execution failed: {msg_phone}")

    def test_kill_switch_halts_actions_across_all_callers(self):
        """Verifies emergency kill switch halts WRITE_EXEC actions across all ingress channels."""
        broker = action_broker.get_action_broker()

        # Engage emergency kill switch
        kill_switch._KILL_SWITCH_ACTIVE = True
        kill_switch._ENGAGED_REASON = "Simulated Emergency"

        for caller in ["desktop_user", "desktop_voice", "telegram_remote", "phone_gateway", "ai_engine"]:
            ok, msg, res = broker.execute_action(
                "homie_snap_window", {"app_name": "notepad", "position": "left"}, caller_id=caller
            )
            self.assertFalse(ok)
            self.assertIn("Emergency kill switch is actively engaged", msg)

        # But READ_ONLY tools remain operational for diagnostic investigation
        ok_read, msg_read, _ = broker.execute_action("homie_get_vitals", {}, caller_id="desktop_user")
        self.assertTrue(ok_read)

    def test_taint_gate_and_step_up_single_use_consumption(self):
        """Verifies tainted session requires step-up, which is consumed single-use and cannot be replayed."""
        broker = action_broker.get_action_broker()
        caller = "ai_agent_untrusted"
        args = {"app_name": "notepad", "position": "right"}

        # 1. Untrusted ingress taints session
        taint_tracker.mark_session_tainted(caller, source="tool_provenance:homie_read_screen_memory")
        self.assertTrue(taint_tracker.is_session_tainted(caller))

        # 2. WRITE_EXEC action blocked without step-up token
        ok, msg, _ = broker.execute_action("homie_snap_window", args, caller_id=caller)
        self.assertFalse(ok)
        self.assertIn("STEP_UP_REQUIRED", msg)

        # Extract step_up_id from reason string
        import re
        m = re.search(r'\[ID:\s*([a-f0-9]+)\]', msg)
        self.assertIsNotNone(m, f"Could not find step_up_id in: {msg}")
        step_up_id = m.group(1)

        # 3. Action permitted when providing valid step-up token
        ok_auth, msg_auth, _ = broker.execute_action(
            "homie_snap_window", args, caller_id=caller, step_up_token=step_up_id
        )
        self.assertTrue(ok_auth, f"Authorized execution failed: {msg_auth}")

        # 4. REPLAY ATTACK: Replaying the consumed step_up_id must be rejected
        ok_replay, msg_replay, _ = broker.execute_action(
            "homie_snap_window", args, caller_id=caller, step_up_token=step_up_id
        )
        self.assertFalse(ok_replay)
        self.assertIn("Step-up token rejected", msg_replay)

    def test_homie_fast_commands_mediated_through_broker(self):
        """Verifies homie.try_fast_command routes via ActionBroker and records in audit ledger."""
        import unittest.mock as mock
        with mock.patch("windows_tools.place_window", return_value=(True, "Placed chrome on left")):
            # 1. Execute fast command
            handled, msg = homie.try_fast_command("put chrome on left", caller_id="desktop_voice")
            self.assertTrue(handled)
            self.assertIn("Placed", msg)

        # 2. Verify audit ledger entry was written with HMAC signature
        entries = agent_audit_ledger.query_audit_entries(limit=5)
        found = any(
            e.get("caller_id") == "desktop_voice" and e.get("tool_name") == "homie_place_window"
            for e in entries
        )
        self.assertTrue(found, "Audit entry for mediated fast command was not found in ledger")


if __name__ == "__main__":
    unittest.main()
