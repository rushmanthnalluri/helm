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

if __name__ == '__main__':
    unittest.main()
