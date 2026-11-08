"""Unit tests for Homie fast instant local commands."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import homie

class TestFastCommands(unittest.TestCase):
    def test_time_command(self):
        handled, msg = homie.try_fast_command("what time is it")
        self.assertTrue(handled)
        self.assertIn("The time is", msg)

    def test_date_command(self):
        handled, msg = homie.try_fast_command("what is today's date")
        self.assertTrue(handled)
        self.assertIn("Today is", msg)

    def test_media_command(self):
        handled, msg = homie.try_fast_command("pause music")
        self.assertTrue(handled)
        self.assertIn("Triggered media key", msg)

    def test_non_fast_command_delegates_to_ai(self):
        handled, msg = homie.try_fast_command("explain quantum computing in detail")
        self.assertFalse(handled)
        self.assertEqual(msg, "")

if __name__ == '__main__':
    unittest.main()
