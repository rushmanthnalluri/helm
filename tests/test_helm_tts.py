"""
Unit tests for Helm NeuralTTS engine:
- Backend selection priority (Kokoro -> Piper -> pyttsx3 -> SAPI5)
- Thread-safe singleton
- Speak, stop, and is_speaking APIs
- SAPI fallback when Kokoro/Piper are absent
- Voice pipeline wiring
"""
import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import helm_tts
from helm_tts import NeuralTTS, BACKEND_KOKORO, BACKEND_PIPER, BACKEND_PYTTSX3, BACKEND_SAPI5
import voice_pipeline


class TestNeuralTTSSingleton(unittest.TestCase):
    def tearDown(self):
        NeuralTTS.reset_instance()

    def test_singleton_returns_same_instance(self):
        inst1 = NeuralTTS.instance()
        inst2 = NeuralTTS.instance()
        self.assertIs(inst1, inst2)

    def test_reset_instance_clears_singleton(self):
        inst1 = NeuralTTS.instance()
        NeuralTTS.reset_instance()
        inst2 = NeuralTTS.instance()
        self.assertIsNot(inst1, inst2)

    def test_singleton_thread_safety(self):
        instances = []

        def worker():
            instances.append(NeuralTTS.instance())

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for inst in instances:
            self.assertIs(inst, instances[0])


class TestNeuralTTSBackendSelection(unittest.TestCase):
    def tearDown(self):
        NeuralTTS.reset_instance()

    def test_primary_backend_kokoro_when_available(self):
        mock_pipeline_cls = MagicMock()
        mock_pipeline_inst = MagicMock()
        mock_pipeline_cls.return_value = mock_pipeline_inst

        with patch.dict("sys.modules", {"kokoro": MagicMock(KPipeline=mock_pipeline_cls)}):
            tts = NeuralTTS()
            backend = tts.backend
            self.assertEqual(backend, BACKEND_KOKORO)
            mock_pipeline_cls.assert_called_once_with(lang_code='a')

    def test_fallback_to_piper_when_kokoro_absent(self):
        mock_piper = MagicMock()
        mock_voice = MagicMock()
        mock_piper.PiperVoice.load.return_value = mock_voice

        # kokoro missing, piper present
        with patch.dict("sys.modules", {"kokoro": None, "piper": mock_piper}):
            tts = NeuralTTS()
            backend = tts.backend
            self.assertEqual(backend, BACKEND_PIPER)
            mock_piper.PiperVoice.load.assert_called_once()

    def test_fallback_to_pyttsx3_when_kokoro_and_piper_absent(self):
        mock_pyttsx3 = MagicMock()
        mock_engine = MagicMock()
        mock_pyttsx3.init.return_value = mock_engine

        # kokoro and piper missing, pyttsx3 present
        with patch.dict("sys.modules", {"kokoro": None, "piper": None, "pyttsx3": mock_pyttsx3}):
            tts = NeuralTTS()
            backend = tts.backend
            self.assertEqual(backend, BACKEND_PYTTSX3)
            mock_pyttsx3.init.assert_called_once()

    def test_fallback_to_sapi5_when_neural_models_absent(self):
        mock_win32com = MagicMock()
        mock_spvoice = MagicMock()
        mock_win32com.client.Dispatch.return_value = mock_spvoice

        with patch.dict("sys.modules", {
            "kokoro": None, 
            "piper": None, 
            "pyttsx3": None, 
            "win32com": mock_win32com, 
            "win32com.client": mock_win32com.client
        }):
            tts = NeuralTTS()
            backend = tts.backend
            self.assertEqual(backend, BACKEND_SAPI5)
            mock_win32com.client.Dispatch.assert_called_with("SAPI.SpVoice")


class TestNeuralTTSSpeakAndStop(unittest.TestCase):
    def tearDown(self):
        NeuralTTS.reset_instance()

    def test_speak_empty_text_ignored(self):
        tts = NeuralTTS.instance()
        tts._do_speak = MagicMock()
        tts.speak("")
        tts.speak("   ")
        tts.speak(None)
        tts._do_speak.assert_not_called()

    def test_speak_kokoro_execution(self):
        tts = NeuralTTS()
        tts._backend = BACKEND_KOKORO
        tts._initialized = True
        
        # Mock Kokoro generator: (graphemes, phonemes, audio_array)
        mock_audio = MagicMock()
        mock_audio.__len__.return_value = 24000
        mock_model = MagicMock(return_value=[("hello", "h-eh-l-ow", mock_audio)])
        tts._model = mock_model

        with patch("sounddevice.play") as mock_play, patch("sounddevice.wait"):
            tts.speak("Hello world", blocking=True)
            mock_model.assert_called_once_with("Hello world", voice='af_heart', speed=1.0)
            mock_play.assert_called_once()

    def test_speak_sapi_execution(self):
        tts = NeuralTTS()
        tts._backend = BACKEND_SAPI5
        tts._initialized = True
        mock_spvoice = MagicMock()
        tts._model = mock_spvoice

        tts.speak("Testing SAPI fallback", blocking=True)
        mock_spvoice.Speak.assert_called_once_with("Testing SAPI fallback", 0)

    def test_stop_clears_flag_and_halts_audio(self):
        tts = NeuralTTS()
        tts._backend = BACKEND_SAPI5
        tts._initialized = True
        mock_spvoice = MagicMock()
        tts._model = mock_spvoice
        tts._is_speaking_flag = True

        with patch("sounddevice.stop") as mock_sd_stop:
            tts.stop()
            self.assertFalse(tts.is_speaking())
            mock_sd_stop.assert_called_once()
            mock_spvoice.Speak.assert_called_once_with("", 2)


class TestVoicePipelineTTSWiring(unittest.TestCase):
    def test_streaming_voice_pipeline_speak_delegation(self):
        pipeline = voice_pipeline.StreamingVoicePipeline(on_transcript=lambda t: None)
        with patch.object(NeuralTTS, "instance") as mock_inst:
            mock_tts = MagicMock()
            mock_inst.return_value = mock_tts

            pipeline.speak("Hello from pipeline", blocking=True)
            mock_tts.speak.assert_called_once_with("Hello from pipeline", blocking=True)

            pipeline.stop_speaking()
            mock_tts.stop.assert_called_once()


if __name__ == '__main__':
    unittest.main()
