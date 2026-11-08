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

    def test_youtube_commands(self):
        # 1. "open youtube and play the loose songs"
        handled, msg = homie.try_fast_command("open youtube and play the loose songs")
        self.assertTrue(handled)
        self.assertIn("YouTube", msg)
        self.assertIn("the loose songs", msg)

        # 2. "Isaid open yt and play songs" (with prefix)
        handled, msg = homie.try_fast_command("Isaid open yt and play songs")
        self.assertTrue(handled)
        self.assertIn("YouTube", msg)

        # 3. "open youtube"
        handled, msg = homie.try_fast_command("open youtube")
        self.assertTrue(handled)
        self.assertIn("YouTube", msg)

        # 4. "play loose songs on youtube"
        handled, msg = homie.try_fast_command("play loose songs on youtube")
        self.assertTrue(handled)
        self.assertIn("YouTube", msg)

    def test_pc_vitals_command(self):
        handled, msg = homie.try_fast_command("pc status")
        self.assertTrue(handled)
        self.assertIn("PC Health Snapshot", msg)
        self.assertIn("RAM:", msg)

    def test_messaging_command_handling(self):
        # Verify messaging commands are caught by fast parser
        handled, msg = homie.try_fast_command("open whatsapp and say hello to Rusman")
        self.assertTrue(handled)
        self.assertIn("WhatsApp", msg)

    def test_non_fast_command_delegates_to_ai(self):
        handled, msg = homie.try_fast_command("explain quantum computing in detail")
        self.assertFalse(handled)
        self.assertEqual(msg, "")

if __name__ == '__main__':
    unittest.main()
