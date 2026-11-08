"""Unit tests for Homie core memory, search, and preferences."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import homie

class TestHomieCore(unittest.TestCase):
    def test_preferences_persistence(self):
        homie.save_pref('test_key', 'test_value')
        prefs = homie.get_prefs()
        self.assertEqual(prefs.get('test_key'), 'test_value')

    def test_memory_rules(self):
        msg = homie.add_rule("Always keep explanations concise")
        self.assertIn("Remembered", msg)
        rules = homie.get_rules()
        self.assertIn("Always keep explanations concise", rules)
        
        del_msg = homie.remove_rule("explanations concise")
        self.assertIn("Removed", del_msg)

    def test_web_search(self):
        res = homie.web_search("python", max_results=2)
        self.assertIsInstance(res, str)
        self.assertIn("python", res.lower())

    def test_safety_check(self):
        self.assertTrue(homie.is_risky("del /f /q C:\\Windows"))
        self.assertTrue(homie.is_risky("rmdir /s /q test"))
        self.assertFalse(homie.is_risky("echo hello world"))

if __name__ == '__main__':
    unittest.main()
