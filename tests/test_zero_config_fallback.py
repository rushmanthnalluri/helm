"""tests/test_zero_config_fallback.py - Verification of Zero-Config First Run & Local Fallback.

Verifies:
1. detect_local_ollama handles both reachable and unreachable states cleanly.
2. get_active_provider defaults to local_offline or ollama when no cloud API keys exist.
3. run_query in local_offline mode executes desktop actions and returns rich zero-config guidance.
4. chat_core.stream_provider_turn runs in local_offline without raising missing-key errors.
5. Existing cloud provider selection remains intact when API keys are configured.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ai_engine
import chat_core


class TestZeroConfigFirstRun(unittest.TestCase):

    def setUp(self):
        # Clear out any ambient environment variables for deterministic tests
        self.orig_env = os.environ.copy()
        for k in ['GEMINI_API_KEY', 'NVIDIA_API_KEY', 'GROQ_API_KEY']:
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_detect_local_ollama_unreachable(self):
        """When Ollama is not running, detect_local_ollama returns available=False without error."""
        with patch("requests.get", side_effect=Exception("Connection refused")):
            res = ai_engine.detect_local_ollama()
            self.assertFalse(res['available'])
            self.assertEqual(res['models'], [])
            self.assertIsNone(res['default_model'])

    def test_detect_local_ollama_reachable(self):
        """When Ollama responds with model list, returns available=True and models."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "models": [{"name": "llama3.2:latest"}, {"name": "qwen2.5:latest"}]
        }
        with patch("requests.get", return_value=mock_resp):
            res = ai_engine.detect_local_ollama()
            self.assertTrue(res['available'])
            self.assertIn("llama3.2:latest", res['models'])
            self.assertEqual(res['default_model'], "llama3.2:latest")

    def test_get_active_provider_zero_config_offline(self):
        """When no API keys exist and Ollama is offline, defaults to local_offline mode."""
        with patch("ai_engine.detect_local_ollama", return_value={'available': False, 'models': [], 'default_model': None, 'base_url': 'http://localhost:11434/v1'}):
            prov = ai_engine.get_active_provider({})
            self.assertEqual(prov['provider'], 'local_offline')
            self.assertIn("Zero-Config", prov['name'])

    def test_get_active_provider_zero_config_ollama(self):
        """When no cloud keys exist but Ollama is running, automatically selects ollama."""
        with patch("ai_engine.detect_local_ollama", return_value={'available': True, 'models': ['mistral:latest'], 'default_model': 'mistral:latest', 'base_url': 'http://localhost:11434/v1'}):
            prov = ai_engine.get_active_provider({})
            self.assertEqual(prov['provider'], 'ollama')
            self.assertEqual(prov['model'], 'mistral:latest')

    def test_get_active_provider_preserves_cloud_key(self):
        """When GEMINI_API_KEY is present, selects gemini provider."""
        os.environ['GEMINI_API_KEY'] = 'test-gemini-key'
        prov = ai_engine.get_active_provider({})
        self.assertEqual(prov['provider'], 'gemini')
        self.assertEqual(prov['api_key'], 'test-gemini-key')

    def test_run_query_local_offline_guidance(self):
        """In local_offline mode, conversational prompt returns helpful onboarding guidance."""
        with patch("ai_engine.detect_local_ollama", return_value={'available': False, 'models': [], 'default_model': None, 'base_url': ''}):
            reply = ai_engine.run_query("Hello who are you?", {})
            self.assertIn("Local Zero-Config Mode", reply)
            self.assertIn("Ollama", reply)
            self.assertNotIn("Please provide a Gemini API Key", reply)

    def test_run_query_local_offline_system_command(self):
        """In local_offline mode, system commands like 'get vitals' execute successfully."""
        with patch("ai_engine.detect_local_ollama", return_value={'available': False, 'models': [], 'default_model': None, 'base_url': ''}):
            with patch("ai_engine.execute_tool", return_value="RAM: 45%, CPU: 12%") as mock_tool:
                reply = ai_engine.run_query("check system vitals", {})
                mock_tool.assert_called_with("get_system_vitals", {})
                self.assertIn("RAM", reply)

    def test_chat_core_stream_turn_local_offline_no_exception(self):
        """chat_core.stream_provider_turn does not raise ProviderError when in zero-config mode."""
        with patch("ai_engine.detect_local_ollama", return_value={'available': False, 'models': [], 'default_model': None, 'base_url': ''}):
            deltas = []
            turn = chat_core.stream_provider_turn(
                messages=[{"role": "user", "content": "hello"}],
                system_prompt="system",
                prefs={},
                tools=[],
                on_delta=lambda d: deltas.append(d)
            )
            self.assertIsNotNone(turn.text)
            self.assertIn("Local Zero-Config Mode", turn.text)
            self.assertTrue(len(deltas) > 0)


if __name__ == '__main__':
    unittest.main()
