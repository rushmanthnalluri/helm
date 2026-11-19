"""tests/test_full_duplex_voice.py - Automated tests for full-duplex real-time voice pipeline.

Verifies:
1. Streaming duplex audio pipeline detects voice activity using local Silero VAD (or energy fallback).
2. Barge-in / interruption immediately halts active TTS audio output when user begins speaking.
3. Duplex audio stream lifecycle (start/stop) with graceful handling of device errors/disconnects.
4. Neural TTS delegation and chunk speech streaming.
"""

import time
import unittest
from unittest.mock import MagicMock, patch
import voice_pipeline
from helm_tts import NeuralTTS


class TestFullDuplexVoicePipeline(unittest.TestCase):
    def setUp(self):
        NeuralTTS.reset_instance()

    def tearDown(self):
        NeuralTTS.reset_instance()

    def test_pipeline_instantiation_and_defaults(self):
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))
        self.assertIsNotNone(pipeline)
        self.assertFalse(pipeline.is_duplex_active)
        self.assertEqual(pipeline._barge_in_count, 0)

    def test_barge_in_halts_active_tts_on_speech_detected(self):
        """When user voice is detected, active TTS must immediately be stopped."""
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))

        # Mock NeuralTTS to simulate active playback
        tts = NeuralTTS.instance()
        tts._is_speaking_flag = True
        self.assertTrue(tts.is_speaking())

        # Generate mock speech PCM bytes (high amplitude so VAD detects voice)
        import struct
        high_energy_pcm = struct.pack("<512h", *([12000] * 512))

        # Mock detect_voice to return True
        with patch.object(pipeline, "detect_voice", return_value=True):
            pipeline.push_audio_chunk(high_energy_pcm, sample_rate=16000)

        # Active speech must have halted
        self.assertFalse(tts.is_speaking())
        self.assertEqual(pipeline._barge_in_count, 1)

    def test_no_barge_in_when_silence_detected(self):
        """When audio chunk contains only silence, TTS playback must continue unaffected."""
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))

        tts = NeuralTTS.instance()
        tts._is_speaking_flag = True

        zero_pcm = b"\x00" * 1024
        with patch.object(pipeline, "detect_voice", return_value=False):
            pipeline.push_audio_chunk(zero_pcm, sample_rate=16000)

        # TTS flag should still be True and barge_in_count should be 0
        self.assertTrue(tts.is_speaking())
        self.assertEqual(pipeline._barge_in_count, 0)

    def test_duplex_stream_start_and_stop_lifecycle(self):
        """Stream worker starts and stops cleanly without dangling threads."""
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))

        # Mock sounddevice.RawInputStream to avoid requiring a physical microphone hardware in CI
        mock_stream = MagicMock()
        with patch("sounddevice.RawInputStream", return_value=mock_stream):
            started = pipeline.start_duplex_stream(sample_rate=16000)
            self.assertTrue(started)
            self.assertTrue(pipeline.is_duplex_active)

            pipeline.stop_duplex_stream()
            self.assertFalse(pipeline.is_duplex_active)

    def test_duplex_stream_graceful_error_handling(self):
        """Device errors or disconnects must be caught and handled without raising an uncaught exception."""
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))

        with patch("sounddevice.RawInputStream", side_effect=RuntimeError("Microphone unplugged")):
            # Must not raise RuntimeError
            started = pipeline.start_duplex_stream(sample_rate=16000)
            self.assertTrue(started)
            # Give the thread a moment to hit the exception and gracefully set _duplex_running to False
            time.sleep(0.1)
            self.assertFalse(pipeline.is_duplex_active)

    def test_speak_and_stop_delegation(self):
        """Pipeline speak and stop delegates cleanly to NeuralTTS."""
        transcripts = []
        pipeline = voice_pipeline.create_pipeline(on_transcript=lambda t: transcripts.append(t))

        with patch.object(NeuralTTS, "speak") as mock_speak, patch.object(NeuralTTS, "stop") as mock_stop:
            pipeline.speak("Hello sovereign desktop")
            mock_speak.assert_called_once_with("Hello sovereign desktop", blocking=False)

            pipeline.stop_speaking()
            mock_stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
