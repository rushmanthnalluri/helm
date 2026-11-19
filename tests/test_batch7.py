"""Unit and integration tests for Batch 7 features:
- Phone Gateway & Web Call API (phone_gateway.py)
- Mobile Remote HTML & Actions (mobile_remote.py)
- Semantic Screen Memory & Recall (semantic_screen_memory.py)
- Claude Chrome Bridge (claude_bridge.py)
- Fast command extensions in helm.py
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

import phone_gateway
import mobile_remote
import semantic_screen_memory
import claude_bridge
import helm

class TestBatch7Features(unittest.TestCase):
    def setUp(self):
        # Ensure gateway stopped before test
        phone_gateway.stop_phone_gateway()

    def tearDown(self):
        phone_gateway.stop_phone_gateway()

    def test_phone_config_load_and_save(self):
        conf = phone_gateway.load_phone_config()
        self.assertIn("port", conf)
        self.assertIn("pin", conf)
        self.assertTrue(conf.get("require_pin", True))

    def test_phone_instruction_execution(self):
        # 1. Fast command execution over phone
        reply = phone_gateway.execute_phone_instruction("what time is it")
        self.assertIn("time is", reply.lower())

        # 2. Vitals over phone
        reply_vitals = phone_gateway.execute_phone_instruction("pc status")
        self.assertIn("RAM", reply_vitals)

    def test_phone_gateway_lifecycle(self):
        ok, msg = phone_gateway.start_phone_gateway(port=5088)
        self.assertTrue(ok)
        self.assertIn("5088", msg)

        # Double start check
        ok2, msg2 = phone_gateway.start_phone_gateway(port=5088)
        self.assertTrue(ok2)
        self.assertIn("already running", msg2.lower())

        # Stop
        ok3, msg3 = phone_gateway.stop_phone_gateway()
        self.assertTrue(ok3)

    def test_mobile_remote_html_rendering(self):
        html = mobile_remote.render_remote_html()
        self.assertIn("Helm PC Remote", html)
        self.assertIn("Trackpad", html)
        self.assertIn("Media & Deck", html)
        self.assertIn("/api/remote-action", html)

    def test_semantic_screen_memory_crud_and_privacy(self):
        # Record normal event
        ok = semantic_screen_memory.record_screen_event("code.exe", "test_batch7.py - helm", "def test_something(): pass")
        self.assertTrue(ok)

        # Record sensitive event (should be blocked)
        ok_sens = semantic_screen_memory.record_screen_event("chrome.exe", "1Password - Master Password Unlock", "secret master key")
        self.assertFalse(ok_sens)

        # Search history
        results = semantic_screen_memory.search_screen_history("test_batch7.py")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["proc_name"], "code.exe")

        # Timeline summary
        summary = semantic_screen_memory.summarize_timeline_text(minutes=10)
        self.assertIn("Screen Timeline", summary)
        self.assertIn("code.exe", summary)

    def test_claude_bridge_window_detection(self):
        # Test detection logic (returns None or dict with HWND)
        win = claude_bridge.find_claude_window()
        if win:
            self.assertIn("hwnd", win)
            self.assertIn("rect", win)

    def test_mobile_device_pairing_tokens(self):
        code, token = phone_gateway.create_mobile_pairing_code(valid_seconds=300)
        self.assertEqual(len(code), 6)
        self.assertGreater(len(token), 16)

        # Exchange
        claimed_token, msg = phone_gateway.exchange_pairing_code_for_token(code, "iPhone Test")
        self.assertEqual(claimed_token, token)
        self.assertTrue(phone_gateway.is_device_token_valid(token))

        # Re-use should fail (single use)
        claimed_again, msg_err = phone_gateway.exchange_pairing_code_for_token(code, "iPhone Test 2")
        self.assertIsNone(claimed_again)

    def test_fast_commands_batch7(self):
        # Phone status fast command
        handled, msg = helm.try_fast_command("phone status")
        self.assertTrue(handled)
        self.assertIn("Phone Gateway", msg)

        # Screen timeline fast command
        handled2, msg2 = helm.try_fast_command("screen timeline")
        self.assertTrue(handled2)
        self.assertIn("Screen Timeline", msg2)

        # Search on screen fast command
        handled3, msg3 = helm.try_fast_command("find on screen test_batch7.py")
        self.assertTrue(handled3)
        self.assertIn("Screen History matches", msg3)

if __name__ == '__main__':
    unittest.main()
