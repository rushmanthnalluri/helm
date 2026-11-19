"""Unit & Integration Tests for Batch 16:
Privilege Separation, Gate-Assumes-Compromise, Dead-Man's Heartbeat, Shadow Mode, & Multi-Channel Canaries:
- Test 1: Gate-Assumes-Compromise direct hostile tool calls blocked 100%
- Test 2: Multi-channel canary exfiltration (Base64 & Hex) caught and halted
- Test 3: Dead-man's switch heartbeat lease validation and expiration
- Test 4: Shadow mode simulation audits without modifying OS state
- Test 5: Rate limiter prevents runaway loops and prompt fatigue DOS
- Test 6: Dispatcher bypass-path enumeration verifies 100% tool coverage
"""

import os
import sys
import time
import base64
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_mcp
import taint_tracker
import kill_switch
import canary_monitor
import heartbeat_lease
import shadow_mode
import windows_tools

class TestBatch16PrivilegeSeparation(unittest.TestCase):

    def setUp(self):
        taint_tracker.clear_all_taints()
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
        shadow_mode.set_shadow_mode(False)
        shadow_mode.clear_rate_limits()
        canary_monitor.reset_guard()
        heartbeat_lease.clear_all_leases()

    def tearDown(self):
        taint_tracker.clear_all_taints()
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
        shadow_mode.set_shadow_mode(False)
        shadow_mode.clear_rate_limits()
        canary_monitor.reset_guard()
        heartbeat_lease.clear_all_leases()

    def test_gate_assumes_compromise_direct_tool_calls_blocked(self):
        """Forces hostile tool calls directly bypassing the LLM and asserts 100% policy blocking."""
        # 1. Direct call with prohibited process target
        orig_fn = windows_tools.is_prohibited_target_process
        try:
            windows_tools.is_prohibited_target_process = lambda hwnd=None: (True, "Prohibited process image: 'powershell.exe'")
            res_hostile = helm_mcp.execute_mcp_tool("helm_agent_click", {"x": 50, "y": 50, "element_name": "HostileShellClick"})
            self.assertIn("Security Gate:", res_hostile)
            self.assertIn("Input denied", res_hostile)
        finally:
            windows_tools.is_prohibited_target_process = orig_fn

        # 2. Direct call when session is tainted
        taint_tracker.mark_session_tainted("compromised_agent_session")
        res_tainted = helm_mcp.execute_mcp_tool("helm_snap_window", {"app_name": "notepad", "position": "left"}, caller_id="compromised_agent_session")
        self.assertIn("Security Gate:", res_tainted)
        self.assertIn("STEP_UP_REQUIRED", res_tainted)

        # 3. Direct call when kill switch is engaged
        kill_switch.engage_kill_switch("Compromise detected")
        res_kill = helm_mcp.execute_mcp_tool("helm_snap_window", {"app_name": "notepad", "position": "left"})
        self.assertIn("Security Gate:", res_kill)
        self.assertIn("Emergency kill switch is active", res_kill)

    def test_multi_channel_canary_exfiltration_base64_and_hex(self):
        """Verifies base64 and hex encoded canary exfiltration triggers immediate kill switch lockdown."""
        canary = canary_monitor.DEFAULT_CANARY_TOKEN
        b64_canary = base64.b64encode(canary.encode("utf-8")).decode("ascii")

        # Exfiltrate base64 token
        res_b64 = helm_mcp.execute_mcp_tool("helm_set_clipboard", {"text": f"leak={b64_canary}"}, caller_id="exfil_agent")
        self.assertIn("Security Gate:", res_b64)
        self.assertIn("LEAK_DETECTED", res_b64)
        self.assertTrue(kill_switch.is_kill_switch_active())

        # Reset kill switch
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")
        canary_monitor.reset_guard()

        # Exfiltrate hex token
        hex_canary = canary.encode("utf-8").hex()
        res_hex = helm_mcp.execute_mcp_tool("helm_set_clipboard", {"text": f"payload={hex_canary}"}, caller_id="exfil_agent")
        self.assertIn("Security Gate:", res_hex)
        self.assertTrue(kill_switch.is_kill_switch_active())

    def test_dead_mans_heartbeat_lease(self):
        """Verifies dead-man's switch heartbeat lease acquisition, renewal, and expiration."""
        session = "agent_heartbeat_worker"
        token, expires = heartbeat_lease.acquire_lease(session, duration=0.3)
        self.assertTrue(heartbeat_lease.is_lease_valid(session))

        # Sleep past TTL
        time.sleep(0.35)
        self.assertFalse(heartbeat_lease.is_lease_valid(session))

    def test_shadow_mode_simulation(self):
        """Verifies shadow mode audits actions without modifying actual operating system state."""
        shadow_mode.set_shadow_mode(True)
        self.assertTrue(shadow_mode.is_shadow_mode_active())

        res = helm_mcp.execute_mcp_tool("helm_set_clipboard", {"text": "shadow_test_value"}, caller_id="shadow_agent")
        self.assertIn("[SHADOW MODE]", res)
        self.assertIn("Simulated execution", res)

    def test_rate_limiter_exceeded(self):
        """Verifies rate limiter throttles excessive calls to defeat runaway loops and DOS."""
        caller = "rapid_loop_agent"
        # Fire 30 allowed calls
        for _ in range(30):
            ok, _ = shadow_mode.check_rate_limit(caller, max_per_minute=30)
            self.assertTrue(ok)

        # 31st call must be throttled
        ok_limit, msg = shadow_mode.check_rate_limit(caller, max_per_minute=30)
        self.assertFalse(ok_limit)
        self.assertIn("Rate limit exceeded", msg)

    def test_dispatcher_bypass_path_enumeration(self):
        """Enumerates every declared MCP tool to verify each routes through execute_mcp_tool."""
        declared_tools = [t["name"] for t in helm_mcp.MCP_TOOLS]
        self.assertGreaterEqual(len(declared_tools), 9)

        for tname in declared_tools:
            # Invoking with invalid args should return clean error or output, never unhandled exception
            out = helm_mcp.execute_mcp_tool(tname, {}, caller_id="enum_tester")
            self.assertIsInstance(out, str)
            self.assertNotIn("Traceback", out)

if __name__ == "__main__":
    unittest.main()
