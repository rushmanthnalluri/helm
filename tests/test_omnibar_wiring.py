"""Tests for floating Omnibar integration and Alt+Space hotkey wiring."""
import unittest
from unittest.mock import MagicMock, patch
import helm_omnibar
import app


class TestOmnibarWiring(unittest.TestCase):
    def test_omnibar_imports(self):
        self.assertIsNotNone(helm_omnibar.HelmOmnibar)
        self.assertIs(helm_omnibar.HelmOmnibar, helm_omnibar.OmnibarController)
        self.assertIsNotNone(app.HelmOmnibar)

    def test_omnibar_initialization_and_callback(self):
        received = []
        bar = helm_omnibar.HelmOmnibar(on_submit=lambda q: received.append(q))
        self.assertIsNotNone(bar.on_submit)
        
        # Test direct submit
        bar.submit("launch terminal")
        self.assertEqual(received, ["launch terminal"])

        # Test agent_ask action
        bar.handle_action("agent_ask", {"query": "weather forecast"})
        self.assertEqual(received, ["launch terminal", "weather forecast"])

    def test_omnibar_toggle_method(self):
        self.assertTrue(hasattr(app.HelmApp, "_toggle_omnibar"))

        mock_app = MagicMock(spec=app.HelmApp)
        mock_bar = MagicMock()
        mock_bar.window = MagicMock()
        mock_app.omnibar = mock_bar

        app.HelmApp._toggle_omnibar(mock_app)
        mock_bar.toggle.assert_called_once()

    def test_omnibar_html_template_exists(self):
        import os
        self.assertTrue(os.path.exists(helm_omnibar.OMNIBAR_HTML_PATH))
        with open(helm_omnibar.OMNIBAR_HTML_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Helm Omnibar", content)
        self.assertIn("agent_ask", content)


if __name__ == "__main__":
    unittest.main()
