"""Unit tests for the Telegram Remote Bridge."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from telegram_bridge import TelegramBridge

class TestTelegramBridge(unittest.TestCase):
    def test_initialization(self):
        bridge = TelegramBridge(token="12345:fake_token", allowed_users=["999"])
        self.assertEqual(bridge.token, "12345:fake_token")
        self.assertIn("999", bridge.allowed_users)

    def test_user_authorization(self):
        bridge = TelegramBridge(token="test", allowed_users=["1001", "1002"])
        # Authorized user
        self.assertTrue(bridge.is_user_authorized(1001, 1001))
        # Unauthorized user
        self.assertFalse(bridge.is_user_authorized(9999, 9999))

    def test_auto_pairing_first_user(self):
        import homie
        orig_users = homie.get_prefs().get('telegramAllowedUsers', [])
        try:
            bridge = TelegramBridge(token="test", allowed_users=[])
            # First user is automatically paired as owner
            self.assertTrue(bridge.is_user_authorized(5555, 5555))
            self.assertIn("5555", bridge.allowed_users)
            # Second user is blocked
            self.assertFalse(bridge.is_user_authorized(7777, 7777))
        finally:
            homie.save_pref('telegramAllowedUsers', orig_users)

if __name__ == '__main__':
    unittest.main()
