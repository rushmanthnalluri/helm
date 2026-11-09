"""Checks that typed and transcribed turns use the shared core and can barge in."""

import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


class FakeSpeech:
    def __init__(self, **kwargs):
        self.chunks = []
        self.finished = False
        self.cancelled = False

    def feed(self, text):
        self.chunks.append(text)

    def finish(self):
        self.finished = True

    def cancel(self):
        self.cancelled = True


class TestChatAppIntegration(unittest.TestCase):
    def test_desktop_ui_has_visible_chat_and_pywebview_controls(self):
        instance = app.HomieApp.__new__(app.HomieApp)

        html = instance.get_ui_html()

        self.assertIn('id="messages"', html)
        self.assertIn('id="ask"', html)
        self.assertIn('pywebview', html)
        self.assertIn('post({minimize: true})', html)
        self.assertNotIn('webkit.messageHandlers', html)

    def test_minimize_button_calls_native_window_minimize(self):
        window = Mock()
        api = app.HomieApi(SimpleNamespace(window=window))

        api.post({"minimize": True})

        window.minimize.assert_called_once_with()

    def test_chat_renders_markdown_as_formatted_text(self):
        instance = app.HomieApp.__new__(app.HomieApp)
        html = instance.get_ui_html()
        self.assertIn("function renderMarkdown(target, value)", html)
        self.assertIn("document.createElement('strong')", html)
        self.assertNotIn("innerHTML", html)

    def test_safe_mode_toggle_updates_to_requested_state(self):
        window = Mock()
        app_instance = SimpleNamespace(window=window, prefs={}, eval_js=Mock())
        api = app.HomieApi(app_instance)

        with patch("app.homie.save_pref"):
            api.post({"safe": False})

        self.assertFalse(app_instance.prefs["safe"])
        app_instance.eval_js.assert_called_once_with("window.ui.mode(false)")

    def test_text_ask_uses_agent_core_and_streams_to_ui(self):
        instance = app.HomieApp.__new__(app.HomieApp)
        instance.prefs = {"speak": False}
        instance.agent_core = Mock()
        instance.eval_js = Mock()
        instance.is_recording = False
        instance._speech_stream_active = threading.Event()

        def fake_turn(text, on_delta, **kwargs):
            on_delta("The answer is 42.")
            return "The answer is 42."

        instance.agent_core.turn.side_effect = fake_turn
        with patch("app.homie.get_prefs", return_value={"speak": False}), \
             patch("app.SentenceSpeechStreamer", FakeSpeech):
            instance.handle_user_ask("What is the answer?", caller_id="desktop_user")

        call = instance.agent_core.turn.call_args
        self.assertEqual(call.args[0], "What is the answer?")
        self.assertEqual(call.kwargs["caller_id"], "desktop_user")
        self.assertIs(call.kwargs["quick_action_handler"], app.homie.try_fast_command)
        self.assertTrue(any("window.ui.line" in item.args[0] and "The answer is 42." in item.args[0]
                            for item in instance.eval_js.call_args_list))

    def test_transcript_enters_same_text_turn_handler(self):
        instance = app.HomieApp.__new__(app.HomieApp)
        instance.voice = SimpleNamespace(transcribe=lambda _audio: "spoken transcript")
        instance.eval_js = Mock()
        instance.handle_user_ask = Mock()

        instance._process_audio(b"audio")

        instance.handle_user_ask.assert_called_once_with(
            "spoken transcript", caller_id="desktop_voice", cancel_event=None
        )

    def test_barge_in_cancels_only_when_assistant_audio_is_active(self):
        instance = app.HomieApp.__new__(app.HomieApp)
        instance.is_recording = False
        instance.paused = False
        instance._speech_stream_active = threading.Event()
        instance.tasks = SimpleNamespace(is_busy=lambda: True)
        instance.voice = SimpleNamespace(start_recording=Mock())
        instance._ask_tasks = []
        instance._ask_tasks_lock = threading.Lock()
        instance.show_window = Mock()
        instance.eval_js = Mock()

        instance.start_listening()
        self.assertFalse(instance.is_recording)
        instance.voice.start_recording.assert_not_called()

        instance._speech_stream_active.set()
        instance.cancel_active_user_turns = Mock()
        instance.start_listening()
        self.assertTrue(instance.is_recording)
        instance.cancel_active_user_turns.assert_called_once_with()
        instance.voice.start_recording.assert_called_once()


if __name__ == "__main__":
    unittest.main()
