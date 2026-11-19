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

import mobile_remote
import semantic_screen_memory
import helm

class TestBatch7Features(unittest.TestCase):
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

        # Record sensitive event (should be blocked when drop_sensitive=True)
        ok_sens = semantic_screen_memory.record_screen_event("chrome.exe", "1Password - Master Password Unlock", "secret master key", drop_sensitive=True)
        self.assertFalse(ok_sens)

        # Search history
        results = semantic_screen_memory.search_screen_history("test_batch7.py")
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["proc_name"], "code.exe")

        # Timeline summary
        summary = semantic_screen_memory.summarize_timeline_text(minutes=10)
        self.assertIn("Screen Timeline", summary)
        self.assertIn("code.exe", summary)

    def test_fast_commands_batch7(self):
        # Phone status fast command (now retired with clear notification)
        handled, msg = helm.try_fast_command("phone status")
        self.assertTrue(handled)
        self.assertIn("Phone gateway has been retired", msg)

        # Screen timeline fast command
        handled2, msg2 = helm.try_fast_command("screen timeline")
        self.assertTrue(handled2)
        self.assertIn("Screen Timeline", msg2)

        # Search on screen fast command
        semantic_screen_memory.record_screen_event("code.exe", "test_batch7.py - helm", "sample content")
        handled3, msg3 = helm.try_fast_command("find on screen test_batch7.py")
        self.assertTrue(handled3)
        self.assertIn("Screen History matches", msg3)

if __name__ == '__main__':
    unittest.main()
