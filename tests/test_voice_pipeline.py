"""
Unit tests for upgraded voice pipeline:
- Silero VAD v5 integration with graceful fallback
- FillerWordFilter regex post-processing
- voice_inject caret text injection
"""
import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import struct
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import voice_pipeline
from voice_pipeline import FillerWordFilter, StreamingVoicePipeline, create_pipeline
import voice_inject
from voice_inject import inject_text_at_caret


class TestFillerWordFilter(unittest.TestCase):
    def setUp(self):
        self.filter = FillerWordFilter()

    def test_strip_basic_filler_words(self):
        text = "Um, hello there, uh, how are you, like, doing?"
        result = self.filter.filter(text)
        words = [w.strip(".,?!") for w in result.lower().split()]
        self.assertNotIn("um", words)
        self.assertNotIn("uh", words)
        self.assertNotIn("like", words)
        self.assertEqual(result, "Hello there how are you doing?")

    def test_strip_you_know(self):
        text = "I think, you know, this works."
        result = self.filter.filter(text)
        self.assertNotIn("you know", result.lower())
        self.assertEqual(result, "I think this works.")

    def test_strip_extended_fillers(self):
        text = "Umm, that was uhh really good, ahh yes."
        result = self.filter(text)
        words = [w.strip(".,?!") for w in result.lower().split()]
        self.assertNotIn("umm", words)
        self.assertNotIn("uhh", words)
        self.assertNotIn("ahh", words)
        self.assertIn("really good", result)

    def test_only_fillers_returns_empty(self):
        text = "Ah, um, like you know"
        result = self.filter.filter(text)
        self.assertEqual(result, "")

    def test_sentence_without_fillers_preserved(self):
        text = "Open Google Chrome and search for documentation."
        result = self.filter.filter(text)
        self.assertEqual(result, text)

    def test_capitalization_preserved_when_leading_filler_removed(self):
        text = "Like, we should proceed."
        result = self.filter.filter(text)
        self.assertEqual(result, "We should proceed.")

    def test_empty_string(self):
        self.assertEqual(self.filter.filter(""), "")
        self.assertEqual(self.filter.filter(None), "")


class TestVoicePipelineSileroVAD(unittest.TestCase):
    def test_pipeline_initialization_defaults(self):
        called = []
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: called.append(t))
        self.assertIsNotNone(pipeline.filler_filter)
        self.assertEqual(pipeline.language, "en")
        self.assertEqual(pipeline.whisper_model_name, "base")

    def test_energy_vad_fallback_on_silence_and_signal(self):
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: None)
        # 512 samples of pure silence (zeros)
        silence = bytes(1024)
        self.assertFalse(pipeline.detect_voice(silence, sample_rate=16000))

        # 512 samples of loud signal (16-bit sine wave)
        samples = [int(15000 * np.sin(2 * np.pi * 440 * i / 16000)) for i in range(512)]
        loud_pcm = struct.pack(f"<{len(samples)}h", *samples)
        self.assertTrue(pipeline.detect_voice(loud_pcm, sample_rate=16000))

    def test_silero_vad_mocked_neural_detection(self):
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: None)
        
        # Mock Silero VAD model
        mock_model = MagicMock()
        # Returns high probability (>0.5) for voice
        prob_tensor = MagicMock()
        prob_tensor.item.return_value = 0.88
        mock_model.return_value = prob_tensor
        pipeline._vad_model = mock_model
        pipeline._vad_initialized = True

        # Generate 16kHz audio chunk of 512 samples
        samples = [int(1000 * np.sin(2 * np.pi * i / 16000)) for i in range(512)]
        pcm_bytes = struct.pack(f"<{len(samples)}h", *samples)

        with patch.dict("sys.modules", {"torch": MagicMock(), "numpy": np}):
            import torch
            mock_tensor = MagicMock()
            mock_tensor.__len__.return_value = 512
            mock_tensor.__getitem__.return_value = mock_tensor
            with patch("torch.from_numpy", return_value=mock_tensor):
                active = pipeline.detect_voice(pcm_bytes, sample_rate=16000)
                self.assertTrue(active)
                mock_model.assert_called()

    def test_graceful_fallback_when_torch_missing(self):
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: None)
        # Force torch import to fail
        with patch.dict("sys.modules", {"torch": None}):
            pipeline._vad_initialized = False
            pipeline._vad_model = None
            silence = bytes(1024)
            # Should not raise exception, falls back to energy VAD
            self.assertFalse(pipeline.detect_voice(silence))

    def test_push_audio_chunk_accumulates_and_transcribes(self):
        transcripts = []
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: transcripts.append(t))
        # Mock _run_whisper directly
        pipeline._run_whisper = MagicMock(return_value="hello world")
        
        # 16-bit loud sample to activate VAD
        samples = [int(15000 * np.sin(2 * np.pi * 440 * i / 16000)) for i in range(512)]
        loud_pcm = struct.pack(f"<{len(samples)}h", *samples)
        silent_pcm = bytes(1024)

        # Send voice frame
        pipeline.push_audio_chunk(loud_pcm)
        self.assertTrue(pipeline._vad_active)

        # Send silence frames up to silence threshold to trigger end-of-speech
        for _ in range(pipeline._SILENCE_THRESHOLD):
            pipeline.push_audio_chunk(silent_pcm)

        self.assertFalse(pipeline._vad_active)

    def test_run_whisper_applies_filler_word_filter(self):
        pipeline = StreamingVoicePipeline(on_transcript=lambda t: None)
        
        # Mock faster_whisper model transcribe return
        segment_mock = MagicMock()
        segment_mock.text = "Um, please open, like, the documents."
        
        mock_whisper = MagicMock()
        mock_whisper.transcribe.return_value = ([segment_mock], None)
        pipeline._model = mock_whisper

        # Dummy audio
        dummy_audio = bytes(1024)
        result = pipeline._run_whisper(dummy_audio, 16000)
        words = [w.strip(".,?!") for w in result.lower().split()]
        self.assertNotIn("um", words)
        self.assertNotIn("like", words)
        self.assertEqual(result, "Please open the documents.")


class TestVoiceInject(unittest.TestCase):
    def test_empty_text_returns_false(self):
        self.assertFalse(inject_text_at_caret(""))
        self.assertFalse(inject_text_at_caret(None))

    def test_direct_paste_success(self):
        with patch("voice_inject._set_clipboard_win32") as mock_clip, \
             patch("voice_inject._send_ctrl_v_sendinput") as mock_send, \
             patch("voice_inject.win32gui.GetForegroundWindow", return_value=12345):
            success = inject_text_at_caret("Hello from Homie!")
            self.assertTrue(success)
            mock_clip.assert_called_once_with("Hello from Homie!")
            mock_send.assert_called_once()

    def test_fallback_paste_when_direct_fails(self):
        with patch("voice_inject._set_clipboard_win32", side_effect=RuntimeError("Clipboard lock failed")), \
             patch("voice_inject._fallback_paste", return_value=True) as mock_fallback:
            success = inject_text_at_caret("Fallback test")
            self.assertTrue(success)
            mock_fallback.assert_called_once_with("Fallback test")


if __name__ == '__main__':
    unittest.main()
