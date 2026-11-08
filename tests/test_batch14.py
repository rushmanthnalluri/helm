"""Unit & Integration Tests for Batch 14:
Process-Image Hardware Grounding, Tool Provenance Flags, & Human-Only Taint Clearance:
- Test 1: Window process info resolution (PID, proc_name, exe_path)
- Test 2: Prohibited process detection (powershell, cmd, wt, telegram, Run dialog)
- Test 3: Agent synthetic click and type hardware blocked on prohibited processes
- Test 4: Tool provenance flags (returns_untrusted) automatically taint session & workstation
- Test 5: Human-only taint clearance rejects untrusted resets and accepts human phone tokens
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import taint_tracker
import homie_mcp

class TestBatch14HardwareTrust(unittest.TestCase):

    def setUp(self):
        taint_tracker.clear_all_taints()

    def tearDown(self):
        taint_tracker.clear_all_taints()

    def test_window_process_info_resolution(self):
        """Verifies resolution of HWND to PID and process executable name."""
        fw = windows_tools.get_foreground_window()
        if fw and fw.get("hwnd"):
            info = windows_tools.get_window_process_info(fw["hwnd"])
            self.assertGreater(info["pid"], 0)
            self.assertTrue(bool(info["proc_name"]))

    def test_prohibited_process_detection(self):
        """Verifies prohibited shells, interpreters, and dialogs are detected."""
        orig_fn = windows_tools.get_window_process_info
        try:
            # Mock process image to powershell.exe
            windows_tools.get_window_process_info = lambda hwnd: {"pid": 1234, "proc_name": "powershell.exe", "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
            blocked, reason = windows_tools.is_prohibited_target_process(99999)
            self.assertTrue(blocked)
            self.assertIn("powershell.exe", reason)

            # Mock process image to telegram.exe
            windows_tools.get_window_process_info = lambda hwnd: {"pid": 5678, "proc_name": "Telegram.exe", "exe_path": "C:\\Program Files\\Telegram\\Telegram.exe"}
            blocked_tg, reason_tg = windows_tools.is_prohibited_target_process(99999)
            self.assertTrue(blocked_tg)
            self.assertIn("telegram.exe", reason_tg)

            # Benign process (notepad.exe) should be permitted
            windows_tools.get_window_process_info = lambda hwnd: {"pid": 9012, "proc_name": "notepad.exe", "exe_path": "C:\\Windows\\notepad.exe"}
            blocked_np, _ = windows_tools.is_prohibited_target_process(99999)
            self.assertFalse(blocked_np)
        finally:
            windows_tools.get_window_process_info = orig_fn

    def test_agent_click_and_type_hardware_blocked(self):
        """Verifies MCP synthetic click and type are blocked when target process is a shell."""
        orig_fn = windows_tools.is_prohibited_target_process
        try:
            windows_tools.is_prohibited_target_process = lambda hwnd=None: (True, "Prohibited process image: 'cmd.exe'")
            res_click = homie_mcp.execute_mcp_tool("homie_agent_click", {"x": 100, "y": 200, "element_name": "BenignButton"})
            self.assertIn("Security Gate: Input denied. Prohibited process image: 'cmd.exe'", res_click)

            res_type = homie_mcp.execute_mcp_tool("homie_agent_type", {"text": "hello", "element_name": "InputBox"})
            self.assertIn("Security Gate: Input denied. Prohibited process image: 'cmd.exe'", res_type)
        finally:
            windows_tools.is_prohibited_target_process = orig_fn

    def test_tool_provenance_flags_trigger_taint(self):
        """Verifies tools with returns_untrusted=True automatically taint session and workstation."""
        session = "clean_test_session"
        self.assertFalse(taint_tracker.is_session_tainted(session))

        # Read clipboard has returns_untrusted: True
        res = homie_mcp.execute_mcp_tool("homie_get_clipboard", {}, caller_id=session)
        self.assertTrue(taint_tracker.is_session_tainted(session))
        status = taint_tracker.get_taint_status(session)
        self.assertIn("tool_provenance:homie_get_clipboard", status["source"])

    def test_human_only_taint_clearance(self):
        """Verifies workstation taint clearance requires explicit human authorization."""
        taint_tracker.mark_session_tainted("session_x")
        self.assertTrue(taint_tracker.is_workstation_tainted())

        # Unauthorized programmatic attempt without human token fails
        ok, msg = taint_tracker.human_clear_taint(None)
        self.assertFalse(ok)
        self.assertIn("Denied", msg)
        self.assertTrue(taint_tracker.is_workstation_tainted())

        # Explicit human phone authorization clears taint
        ok_human, msg_human = taint_tracker.human_clear_taint("human_token_phone_approval_123")
        self.assertTrue(ok_human)
        self.assertFalse(taint_tracker.is_workstation_tainted())

if __name__ == "__main__":
    unittest.main()
