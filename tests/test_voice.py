"""Unit tests for VoiceEngine audio level processing."""
import unittest
import sys
import os
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from voice import VoiceEngine

class TestVoiceEngine(unittest.TestCase):
    def test_voice_initialization(self):
        engine = VoiceEngine(model_size="tiny", language="en")
        self.assertEqual(engine.sample_rate, 16000)
        self.assertFalse(engine.recording)

    def test_level_computation(self):
        levels = []
        engine = VoiceEngine()
        engine.recording = True
        engine.level_callback = lambda l: levels.append(l)

        # Feed 100ms of simulated audio wave
        t = np.linspace(0, 0.1, 1600, endpoint=False, dtype=np.float32)
        sine_wave = 0.5 * np.sin(2 * np.pi * 440 * t)
        sine_wave = sine_wave.reshape(-1, 1)

        engine._audio_callback(sine_wave, len(sine_wave), None, None)
        self.assertGreater(len(levels), 0)
        self.assertGreater(levels[0], 0.0)

if __name__ == '__main__':
    unittest.main()
