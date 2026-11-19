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

    def test_unpaired_bot_requires_local_pairing_code(self):
        import helm
        orig_users = helm.get_prefs().get('telegramAllowedUsers', [])
        try:
            bridge = TelegramBridge(token="test", allowed_users=[])
            # A Telegram message alone cannot claim an unpaired PC.
            self.assertRegex(bridge.get_pairing_command(), r"^/pair [A-HJ-NP-Z2-9]{10}$")
            self.assertFalse(bridge.is_user_authorized(5555, 5555))
            self.assertEqual(bridge.allowed_users, [])
            # All unpaired senders remain blocked until local approval.
            self.assertFalse(bridge.is_user_authorized(7777, 7777))
        finally:
            helm.save_pref('telegramAllowedUsers', orig_users)

    def test_message_chunking(self):
        import unittest.mock as mock
        bridge = TelegramBridge(token="test", allowed_users=["1001"])
        sent_chunks = []
        with mock.patch.object(bridge, '_api_call', side_effect=lambda method, data=None, files=None, timeout=30: sent_chunks.append(data['text']) or True):
            # 5000 character message should be chunked into at least 2 pieces
            long_msg = "A" * 2500 + "\n" + "B" * 2500
            bridge.send_message(1001, long_msg)
            self.assertGreaterEqual(len(sent_chunks), 2)
            for c in sent_chunks:
                self.assertLessEqual(len(c), 4000)

    def test_command_routing(self):
        import unittest.mock as mock
        bridge = TelegramBridge(token="test", allowed_users=["1001"])
        replies = []
        with mock.patch.object(bridge, 'send_message', side_effect=lambda cid, text: replies.append(text)):
            # 1. /clip
            bridge.handle_command(1001, "/clip HelloClipboardFromTest")
            self.assertTrue(any("clipboard" in r.lower() for r in replies))

            # 2. /cmd
            replies.clear()
            bridge.handle_command(1001, "/cmd echo HelmCmdTest")
            self.assertTrue(any("helmcmdtest" in r.lower() for r in replies))

            # 3. /rules
            replies.clear()
            bridge.handle_command(1001, "/rules")
            self.assertTrue(any("memory" in r.lower() or "no rules" in r.lower() for r in replies))

    def test_control_panel_and_callbacks(self):
        import unittest.mock as mock
        bridge = TelegramBridge(token="test", allowed_users=["1001"])
        
        # Test control panel markup structure
        panel = bridge.get_control_panel_markup()
        self.assertIn("inline_keyboard", panel)
        self.assertGreaterEqual(len(panel["inline_keyboard"]), 3)

        # Test callback handling
        replies = []
        with mock.patch.object(bridge, 'answer_callback_query'), mock.patch.object(bridge, 'send_message', side_effect=lambda cid, text, **kw: replies.append(text)):
            bridge.handle_callback(1001, "cb_1", "action_mute")
            self.assertTrue(any("Triggered media key" in r for r in replies))

            # Test confirmation guardrail
            bridge.request_confirmation(1001, "Test Kill", "close_app", "notepad")
            self.assertEqual(len(bridge.pending_actions), 1)
            action_id = list(bridge.pending_actions.keys())[0]

            # Confirm action
            replies.clear()
            with mock.patch("windows_tools.close_app", return_value=(True, "Closed notepad.")):
                bridge.handle_callback(1001, "cb_2", f"confirm_action_{action_id}")
                self.assertTrue(any("Closed notepad" in r for r in replies))

if __name__ == '__main__':
    unittest.main()
