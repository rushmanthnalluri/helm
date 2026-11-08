"""Unit tests for the multi-provider AI Engine (Gemini, NVIDIA NIM, Groq, Ollama)."""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import ai_engine

class TestAiEngine(unittest.TestCase):
    def test_provider_resolution(self):
        # Gemini resolution
        gemini_prov = ai_engine.get_active_provider({'provider': 'gemini', 'geminiKey': 'test_key'})
        self.assertEqual(gemini_prov['provider'], 'gemini')
        self.assertIn('generativelanguage.googleapis.com', gemini_prov['base_url'])
        self.assertEqual(gemini_prov['api_key'], 'test_key')

        # NVIDIA NIM resolution
        nvidia_prov = ai_engine.get_active_provider({'provider': 'nvidia', 'nvidiaKey': 'nv_key'})
        self.assertEqual(nvidia_prov['provider'], 'nvidia')
        self.assertIn('integrate.api.nvidia.com', nvidia_prov['base_url'])
        self.assertEqual(nvidia_prov['api_key'], 'nv_key')

        # Groq resolution
        groq_prov = ai_engine.get_active_provider({'provider': 'groq', 'groqKey': 'gr_key'})
        self.assertEqual(groq_prov['provider'], 'groq')
        self.assertIn('api.groq.com', groq_prov['base_url'])

    def test_tool_execution(self):
        msg = ai_engine.execute_tool('media_control', {'action': 'mute'})
        self.assertIn('mute', msg)

if __name__ == '__main__':
    unittest.main()
