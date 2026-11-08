"""Fuzzing and security integration test harness for Homie.
Tests robustness and security guardrails against:
- Malicious shell metacharacter injections (&, |, ;, $(), ``, etc.)
- Buffer overflows / ultra-long input fuzzing (10,000+ chars)
- Unicode edge cases, null bytes, and non-printable control chars
- Phone gateway malformed payloads and unauthorized token tampering
- MCP JSON-RPC protocol edge cases and error bounds
"""

import os
import sys
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import homie
import homie_mcp
import pipeline_telemetry
import phone_gateway
import voice

class TestFuzzAndGuardrails(unittest.TestCase):
    def test_command_injection_fuzzing(self):
        """Fuzzes windows_tools.execute_safe_command with hostile shell metacharacters."""
        malicious_payloads = [
            "notepad.exe; calc.exe",
            "notepad.exe && dir",
            "notepad.exe | whoami",
            "notepad.exe & format c:",
            "notepad.exe `calc`",
            "notepad.exe $(calc.exe)",
            "calc.exe\nwhoami",
            "notepad.exe\r\ndir",
            "rmdir /s /q c:\\",
            "powershell -enc AAA",
            "del /f /q *.*",
            "shutdown /s /t 0",
            "notepad \0 calc.exe"
        ]

        for payload in malicious_payloads:
            ok, output = windows_tools.execute_safe_command(payload)
            # Safe mode MUST either reject or block dangerous metacharacters
            self.assertFalse(ok, f"Hostile payload should have been blocked: {payload}")
            self.assertTrue(any(term in output.lower() for term in ["blocked", "unsafe", "rejected", "forbidden", "invalid", "safe mode"]),
                            f"Output missing security denial reason: {output}")

    def test_fast_command_fuzzing_massive_strings(self):
        """Tests that fast command parser never crashes on 10,000+ character gibberish."""
        massive_string = "open " + ("a" * 15000)
        handled, msg = homie.try_fast_command(massive_string)
        # Should gracefully return without crashing
        self.assertIsInstance(handled, bool)

        random_unicode = "⚡✨🔥🎉 " * 500 + "\x00\x01\x02\x03\t\r\n"
        handled2, msg2 = homie.try_fast_command(random_unicode)
        self.assertIsInstance(handled2, bool)

    def test_mcp_jsonrpc_fuzzing(self):
        """Fuzzes Homie MCP server with malformed JSON-RPC requests."""
        # 1. Unknown method
        res1 = homie_mcp.handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "non_existent_method"})
        self.assertIn("error", res1)
        self.assertEqual(res1["error"]["code"], -32601)

        # 2. Tools call with missing parameters
        res2 = homie_mcp.handle_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "homie_snap_window", "arguments": {}}
        })
        self.assertIn("result", res2)
        self.assertIn("content", res2["result"])

        # 3. Unknown tool name
        res3 = homie_mcp.handle_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "non_existent_tool", "arguments": {}}
        })
        self.assertIn("Unknown tool", res3["result"]["content"][0]["text"])

    def test_phone_gateway_auth_tampering(self):
        """Fuzzes phone gateway token verification with tampered, empty, and fake tokens."""
        self.assertFalse(phone_gateway.is_device_token_valid(""))
        self.assertFalse(phone_gateway.is_device_token_valid(None))
        self.assertFalse(phone_gateway.is_device_token_valid("invalid_token_12345"))
        self.assertFalse(phone_gateway.is_device_token_valid("'; DROP TABLE paired_mobile_devices; --"))

    def test_voice_bargein_and_silence(self):
        """Verifies stop_speaking barge-in and silence fast commands."""
        res = voice.stop_speaking()
        self.assertIsInstance(res, bool)

        handled, msg = homie.try_fast_command("shut up")
        self.assertTrue(handled)
        self.assertEqual(msg, "Silenced.")

    def test_pipeline_telemetry_tracking(self):
        """Verifies telemetry stage tracking and latency calculation."""
        tracker = pipeline_telemetry.LatencyTracker(command_text="snap window left", path_type="fast")
        tracker.start_stage()
        # simulate fast stage
        tracker.end_stage("intent")
        tracker.start_stage()
        tracker.end_stage("action")
        event = tracker.finish()

        self.assertGreaterEqual(event["total_ms"], 0.0)
        self.assertEqual(event["path_type"], "fast")

        rep = pipeline_telemetry.format_telemetry_report()
        self.assertIn("Pipeline Telemetry", rep)

if __name__ == '__main__':
    unittest.main()
