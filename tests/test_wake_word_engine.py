"""Tests for the live local wake-word listener and desktop turn handoff."""

import threading
import time
import unittest
from unittest.mock import Mock, patch

import numpy as np

import app
import wake_word_engine


class FakeInputStream:
    instances = []

    def __init__(self, **kwargs):
        self.callback = kwargs["callback"]
        self.closed = False
        self.started = False
        self.__class__.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        pass

    def close(self):
        self.closed = True


class FakeLocalVoice:
    _loading_model = False

    def transcribe_local(self, audio, beam_size=1):
        return "Hey Helm, what time is it?"


class TestWakeWordEngine(unittest.TestCase):
    def setUp(self):
        FakeInputStream.instances.clear()

    def test_live_listener_uses_local_transcript_and_releases_mic_before_callback(self):
        woke = threading.Event()
        callback_state = {}

        def on_wake(timestamp):
            callback_state["timestamp"] = timestamp
            callback_state["closed"] = FakeInputStream.instances[-1].closed
            woke.set()

        detector = wake_word_engine.WakeWordDetector(
            wake_word="Helm",
            voice_engine=FakeLocalVoice(),
            on_wake_callback=on_wake,
        )
        with patch("wake_word_engine.voice.sd.InputStream", FakeInputStream), \
             patch("wake_word_engine.voice.stop_speaking"):
            ok, _ = detector.start()
            self.assertTrue(ok)
            stream = FakeInputStream.instances[-1]
            speech = np.full((1600, 1), 0.05, dtype=np.float32)
            silence = np.zeros((1600, 1), dtype=np.float32)
            for _ in range(4):
                stream.callback(speech, len(speech), None, None)
            for _ in range(9):
                stream.callback(silence, len(silence), None, None)

            self.assertTrue(woke.wait(3.0), "Wake word should be detected from the local transcript")
            self.assertTrue(callback_state["closed"], "Listener must release the mic before app handoff")
            self.assertEqual(detector.command_after_wake_word(), "what time is it?")
            self.assertFalse(detector.is_running)
            detector.stop()

    def test_partial_word_does_not_trigger_wake(self):
        detector = wake_word_engine.WakeWordDetector()
        self.assertFalse(detector.process_audio_chunk(b"", "The helms are here"))

    def test_desktop_wake_handoff_routes_words_after_name_to_voice_turn(self):
        instance = app.HelmApp.__new__(app.HelmApp)
        instance.prefs = {"wakeWord": True}
        instance._wake_word_enabled = True
        instance.paused = False
        instance.wake_word_detector = Mock()
        instance.wake_word_detector.last_transcript = "Hey Helm, what time is it?"
        instance.wake_word_detector.command_after_wake_word.return_value = "what time is it?"
        instance.show_window = Mock()
        instance.submit_user_turn = Mock()
        instance._handle_wake_word_request = Mock()

        instance._on_wake_word(time.time())

        instance.show_window.assert_called_once_with()
        instance.submit_user_turn.assert_called_once_with(
            "wake_word_request",
            instance._handle_wake_word_request,
            "what time is it?",
        )


if __name__ == "__main__":
    unittest.main()
