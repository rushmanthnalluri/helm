"""Unit tests for Homie Windows automation tools."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import windows_tools

class TestWindowsTools(unittest.TestCase):
    def test_get_monitors(self):
        monitors = windows_tools.get_monitors()
        self.assertIsInstance(monitors, list)
        self.assertGreaterEqual(len(monitors), 1)
        m = monitors[0]
        self.assertIn('width', m)
        self.assertIn('height', m)
        self.assertGreater(m['width'], 0)
        self.assertGreater(m['height'], 0)

    def test_find_windows(self):
        wins = windows_tools.find_windows()
        self.assertIsInstance(wins, list)

    def test_media_control(self):
        ok, msg = windows_tools.control_media('mute')
        self.assertTrue(ok)
        self.assertIn('mute', msg)

    def test_capture_screens(self):
        paths = windows_tools.capture_screens()
        self.assertIsInstance(paths, list)
        self.assertGreater(len(paths), 0)
        for p in paths:
            self.assertTrue(os.path.exists(p))

    def test_system_vitals(self):
        v = windows_tools.get_system_vitals()
        self.assertIsInstance(v, dict)
        self.assertIn('ram_pct', v)
        self.assertIn('disk_free_gb', v)
        self.assertIn('battery', v)
        self.assertIn('uptime_hours', v)
        self.assertGreater(v['ram_pct'], 0)

    def test_ensure_desktop_attached(self):
        # Should execute safely without raising
        windows_tools.ensure_desktop_attached()

    def test_clipboard_operations(self):
        ok, msg = windows_tools.set_clipboard_text("HomieTestClipboardValue")
        self.assertTrue(ok)
        val = windows_tools.get_clipboard_text()
        self.assertEqual(val, "HomieTestClipboardValue")

    def test_safe_command_execution(self):
        # Safe command should succeed
        ok, out = windows_tools.execute_safe_command("echo HomieOnline")
        self.assertTrue(ok)
        self.assertIn("HomieOnline", out)

        # Destructive command should be blocked by guardrails
        ok_blocked, out_blocked = windows_tools.execute_safe_command("rmdir /s /q C:\\Windows")
        self.assertFalse(ok_blocked)
        self.assertIn("guardrail", out_blocked.lower())

    def test_list_downloads(self):
        items = windows_tools.list_downloads(limit=5)
        self.assertIsInstance(items, list)

if __name__ == '__main__':
    unittest.main()
