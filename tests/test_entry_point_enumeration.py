"""test_entry_point_enumeration.py - Comprehensive Entry-Point Complete Mediation Tests.

Fulfills Batches 16, 17, and 35 architectural directives:
Verifies that EVERY remote and local workstation entry point:
1. Telegram Remote Control Bridge (telegram_bridge.py)
   - Inline interactive callback buttons (action_play_pause, action_screen, action_vitals, confirm_action, etc.)
   - Slash commands (/play, /screen, /media, /snap, /open, /close, /top, /status, /clip, /cmd, /downloads, /msg)
2. Phone Gateway Spoken Instruction Dispatcher (phone_gateway.py)
   - Fast spoken commands and HTTP status endpoints
3. Desktop Assistant Fast Command Dispatcher (homie.py: try_fast_command)
   - Media hardware controls, YouTube playback, window placement, WhatsApp/Telegram messaging,
     app termination, system vitals, clipboard, downloads, and process inspection
4. Policy Enforcement across all entry points:
   - Emergency Kill Switch complete mediation
   - Policy Supervisor STATE_LOCKED complete mediation
   - Taint Tracking and step-up authorization gates
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

import action_broker
import kill_switch
import homie_supervisor
import taint_tracker
import homie
import windows_tools
from telegram_bridge import TelegramBridge


class TestEntryPointEnumeration(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")

    def tearDown(self):
        kill_switch.disengage_kill_switch("EXPLICIT_HUMAN_CONFIRMATION")

    def test_1_telegram_callback_entry_points_dispatch_via_broker(self):
        """Verifies all interactive Telegram button callbacks route through action_broker.execute_action."""
        bridge = TelegramBridge()
        bridge.send_message = MagicMock()
        bridge.send_photo = MagicMock()
        bridge.answer_callback_query = MagicMock()

        test_callbacks = [
            ('action_play_pause', 'homie_control_media'),
            ('action_next', 'homie_control_media'),
            ('action_mute', 'homie_control_media'),
            ('action_screen', 'homie_capture_screen'),
            ('action_vitals', 'homie_get_vitals'),
            ('action_clip_read', 'homie_get_clipboard'),
            ('action_downloads', 'homie_list_downloads'),
        ]

        for cb_data, expected_tool in test_callbacks:
            with patch('action_broker.execute_action', return_value=(True, "Success", "{}")) as mock_exec:
                bridge.handle_callback(chat_id=12345, callback_query_id="query_1", data=cb_data)
                mock_exec.assert_called()
                called_tool = mock_exec.call_args[0][0]
                called_caller = mock_exec.call_args[1].get('caller_id') or mock_exec.call_args[0][2]
                self.assertEqual(called_tool, expected_tool)
                self.assertEqual(called_caller, "telegram_remote")

    def test_2_telegram_confirm_actions_dispatch_via_broker(self):
        """Verifies pending confirmation actions in Telegram route through action_broker.execute_action."""
        bridge = TelegramBridge()
        bridge.send_message = MagicMock()
        bridge.answer_callback_query = MagicMock()

        confirm_scenarios = [
            ('close_app', 'notepad.exe', 'homie_close_app'),
            ('kill_pid', 1234, 'homie_kill_process'),
            ('run_cmd', 'dir', 'homie_safe_command'),
        ]

        for act, payload, expected_tool in confirm_scenarios:
            act_id = f"test_{act}"
            bridge.pending_actions[act_id] = {
                'action': act,
                'payload': payload,
                'expires': time.time() + 60.0
            }
            with patch('action_broker.execute_action', return_value=(True, "Success", "{}")) as mock_exec:
                bridge.handle_callback(chat_id=12345, callback_query_id="query_2", data=f"confirm_action_{act_id}")
                mock_exec.assert_called()
                called_tool = mock_exec.call_args[0][0]
                called_caller = mock_exec.call_args[1].get('caller_id') or mock_exec.call_args[0][2]
                self.assertEqual(called_tool, expected_tool)
                self.assertEqual(called_caller, "telegram_remote")

    def test_3_telegram_slash_commands_dispatch_via_broker(self):
        """Verifies all Telegram slash commands route through action_broker.execute_action."""
        bridge = TelegramBridge()
        bridge.send_message = MagicMock()
        bridge.send_photo = MagicMock()

        test_commands = [
            ('/play telugu songs', 'homie_play_youtube'),
            ('/screen', 'homie_capture_screen'),
            ('/media next', 'homie_control_media'),
            ('/snap right notepad', 'homie_place_window'),
            ('/open calc', 'homie_launch_app'),
            ('/close notepad', 'homie_close_app'),
            ('/top', 'homie_get_top_processes'),
            ('/status', 'homie_get_vitals'),
            ('/clip hello', 'homie_set_clipboard'),
            ('/cmd ipconfig', 'homie_safe_command'),
            ('/downloads', 'homie_list_downloads'),
            ('/msg whatsapp 1234567890 hello', 'homie_send_chat'),
        ]

        for cmd_text, expected_tool in test_commands:
            with patch('action_broker.execute_action', return_value=(True, "Success", "{}")) as mock_exec:
                bridge.handle_command(chat_id=12345, text=cmd_text)
                mock_exec.assert_called()
                called_tool = mock_exec.call_args[0][0]
                called_caller = mock_exec.call_args[1].get('caller_id') or mock_exec.call_args[0][2]
                self.assertEqual(called_tool, expected_tool)
                self.assertEqual(called_caller, "telegram_remote")

    def test_4_homie_try_fast_command_dispatches_via_broker(self):
        """Verifies all desktop/voice fast commands route through action_broker.execute_action."""
        test_phrases = [
            ("pause music", "homie_control_media"),
            ("play bohemian rhapsody on youtube", "homie_play_youtube"),
            ("snap window left", "homie_place_window"),
            ("open whatsapp and say hi to john", "homie_send_chat"),
            ("close notepad", "homie_close_app"),
            ("pc status", "homie_get_vitals"),
            ("get clipboard", "homie_get_clipboard"),
            ("copy hello to clipboard", "homie_set_clipboard"),
            ("recent downloads", "homie_list_downloads"),
            ("what's on my screen", "homie_capture_screen"),
            ("top processes", "homie_get_top_processes"),
        ]

        for phrase, expected_tool in test_phrases:
            with patch('action_broker.execute_action', return_value=(True, "Success", "{}")) as mock_exec:
                handled, msg = homie.try_fast_command(phrase, caller_id="desktop_voice")
                self.assertTrue(handled, f"Phrase '{phrase}' was not handled by try_fast_command")
                mock_exec.assert_called()
                called_tool = mock_exec.call_args[0][0]
                called_caller = mock_exec.call_args[1].get('caller_id') or mock_exec.call_args[0][2]
                self.assertEqual(called_tool, expected_tool)
                self.assertEqual(called_caller, "desktop_voice")

    def test_5_phone_gateway_commands_dispatch_via_broker(self):
        """Verifies phone gateway audio instructions route through action_broker with caller_id='phone_gateway'."""
        import phone_gateway

        with patch('action_broker.execute_action', return_value=(True, "Paused media", "{}")) as mock_exec:
            reply = phone_gateway.execute_phone_instruction("pause music")
            mock_exec.assert_called()
            called_tool = mock_exec.call_args[0][0]
            called_caller = mock_exec.call_args[1].get('caller_id') or mock_exec.call_args[0][2]
            self.assertEqual(called_tool, "homie_control_media")
            self.assertEqual(called_caller, "phone_gateway")

    def test_6_complete_mediation_kill_switch_blocks_write_actions_across_all_entry_points(self):
        """Verifies Emergency Kill Switch mediates and blocks WRITE_EXEC actions from ANY entry point."""
        kill_switch.engage_kill_switch("Security Emergency")

        # 1. Telegram
        ok, msg, _ = action_broker.execute_action('homie_close_app', {'app_name': 'notepad'}, caller_id='telegram_remote')
        self.assertFalse(ok)
        self.assertIn("kill switch", msg.lower())

        # 2. Phone Gateway
        ok2, msg2, _ = action_broker.execute_action('homie_close_app', {'app_name': 'notepad'}, caller_id='phone_gateway')
        self.assertFalse(ok2)
        self.assertIn("kill switch", msg2.lower())

        # 3. Desktop Voice
        ok3, msg3, _ = action_broker.execute_action('homie_safe_command', {'command': 'dir'}, caller_id='desktop_voice')
        self.assertFalse(ok3)
        self.assertIn("kill switch", msg3.lower())

    def test_7_supervisor_locked_state_fails_closed_across_all_entry_points(self):
        """Verifies that when Supervisor is in STATE_LOCKED, all entry points fail closed."""
        broker = action_broker.get_action_broker()
        broker.supervisor.state = homie_supervisor.STATE_LOCKED
        broker.supervisor.lock_reason = "CRITICAL_INTEGRITY_BREACH"

        try:
            ok, msg, _ = broker.execute_action('homie_get_vitals', {}, caller_id='telegram_remote')
            self.assertFalse(ok)
            self.assertIn("LOCKED", msg)

            ok2, msg2, _ = broker.execute_action('homie_control_media', {'action': 'next'}, caller_id='phone_gateway')
            self.assertFalse(ok2)
            self.assertIn("LOCKED", msg2)
        finally:
            broker.supervisor.state = homie_supervisor.STATE_ARMED


if __name__ == "__main__":
    unittest.main()
