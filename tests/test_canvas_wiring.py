"""Tests for interactive Side Canvas (Artifacts 2.0) integration and wiring."""
import os
import unittest
from unittest.mock import MagicMock, patch

import helm_canvas
import app
import helm


class TestCanvasWiring(unittest.TestCase):
    def test_canvas_imports(self):
        """Verifies Canvas module exports and safe imports in app.py."""
        self.assertIsNotNone(helm_canvas.HelmCanvas)
        self.assertIs(helm_canvas.HelmCanvas, helm_canvas.CanvasController)
        self.assertIsNotNone(app.HelmCanvas)
        self.assertIs(app.HelmCanvas, helm_canvas.CanvasController)
        self.assertIsNotNone(helm_canvas.get_canvas())
        self.assertIsInstance(helm_canvas.get_canvas(), helm_canvas.CanvasController)

    def test_canvas_initialization_and_visibility(self):
        """Verifies CanvasController state management and visibility toggling."""
        controller = helm_canvas.CanvasController()
        self.assertFalse(controller.is_visible)
        self.assertIsNone(controller.window)

        # Mock window
        mock_window = MagicMock()
        controller.window = mock_window

        controller.show()
        self.assertTrue(controller.is_visible)
        mock_window.show.assert_called_once()
        mock_window.restore.assert_called_once()

        controller.hide()
        self.assertFalse(controller.is_visible)
        mock_window.hide.assert_called_once()

        controller.toggle()
        self.assertTrue(controller.is_visible)

        controller.toggle()
        self.assertFalse(controller.is_visible)

    def test_canvas_show_artifact_and_payload_formatting(self):
        """Verifies artifact rendering, type normalization, and payload structure."""
        controller = helm_canvas.CanvasController()
        mock_window = MagicMock()
        controller.window = mock_window

        # 1. Document / Markdown
        res = controller.show_artifact(
            title="Q3 Strategy Report",
            content="# Executive Summary\n- Key revenue up 25%\n- New product launch",
            content_type="markdown",
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["title"], "Q3 Strategy Report")
        self.assertEqual(res["type"], "document")
        self.assertEqual(res["status"], "displayed_in_canvas")

        active = controller.active_artifact
        self.assertIsNotNone(active)
        self.assertIn("<h1", active["html_content"])
        self.assertIn("<li", active["html_content"])
        self.assertTrue(controller.is_visible)
        mock_window.evaluate_js.assert_called()

        # 2. Python Code Snippet
        code_res = controller.show_artifact(
            title="Data Pipeline",
            content="def process_data(df):\n    return df.dropna()",
            content_type="python",
        )
        self.assertTrue(code_res["ok"])
        self.assertEqual(code_res["type"], "code")
        self.assertIn("<pre", controller.active_artifact["html_content"])
        self.assertIn("process_data", controller.active_artifact["html_content"])

        # 3. Mermaid Diagram
        mermaid_res = controller.show_artifact(
            title="System Architecture",
            content="graph TD\nA[Client] --> B[API Gateway]",
            content_type="mermaid",
        )
        self.assertTrue(mermaid_res["ok"])
        self.assertEqual(mermaid_res["type"], "mermaid")
        self.assertIn("class=\"mermaid\"", controller.active_artifact["html_content"])

        # 4. Global active artifact is synchronized
        global_active = helm_canvas.get_active_artifact()
        self.assertIsNotNone(global_active)
        self.assertEqual(global_active["title"], "System Architecture")

    def test_app_canvas_methods(self):
        """Verifies HelmApp.toggle_canvas and HelmApp.show_artifact_on_canvas."""
        self.assertTrue(hasattr(app.HelmApp, "toggle_canvas"))
        self.assertTrue(hasattr(app.HelmApp, "show_artifact_on_canvas"))

        mock_app = MagicMock(spec=app.HelmApp)
        mock_canvas = MagicMock()
        mock_canvas.window = MagicMock()
        mock_app.canvas = mock_canvas

        # Call toggle_canvas
        app.HelmApp.toggle_canvas(mock_app)
        mock_canvas.toggle.assert_called_once()

        # Call show_artifact_on_canvas
        app.HelmApp.show_artifact_on_canvas(
            mock_app,
            title="Widget Test",
            content="<div>Hello Canvas</div>",
            content_type="html",
        )
        mock_canvas.show_artifact.assert_called_once_with(
            title="Widget Test",
            content="<div>Hello Canvas</div>",
            content_type="html",
        )

    def test_extract_artifacts_from_markdown_and_tags(self):
        """Verifies artifact extraction from AI turns with fenced code and artifact tags."""
        text_with_code = (
            "Here is the algorithm requested:\n\n"
            "```python\n"
            "def fib(n):\n"
            "    return n if n <= 1 else fib(n-1) + fib(n-2)\n"
            "```\n\n"
            "And here is the visual flowchart:\n"
            "```mermaid\n"
            "graph LR\n"
            "Start --> Step1 --> End\n"
            "```"
        )
        extracted = helm_canvas.extract_artifacts(text_with_code)
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted[0]["type"], "code")
        self.assertIn("fib(n)", extracted[0]["content"])
        self.assertEqual(extracted[1]["type"], "mermaid")
        self.assertIn("Start --> Step1", extracted[1]["content"])

        # XML / HTML-style artifact tags
        text_with_tag = (
            "I generated the sales forecast for you:\n"
            '<artifact title="Q4 Sales Projections" type="document">\n'
            "# Sales Projections\n"
            "Projected revenue exceeds expectations.\n"
            "</artifact>"
        )
        tag_extracted = helm_canvas.extract_artifacts(text_with_tag)
        self.assertEqual(len(tag_extracted), 1)
        self.assertEqual(tag_extracted[0]["title"], "Q4 Sales Projections")
        self.assertEqual(tag_extracted[0]["type"], "document")
        self.assertTrue(tag_extracted[0].get("from_tag"))

    def test_canvas_html_template_exists(self):
        """Verifies that ui/canvas.html exists and contains the Artifacts 2.0 interface."""
        self.assertTrue(os.path.exists(helm_canvas.CANVAS_HTML_PATH))
        with open(helm_canvas.CANVAS_HTML_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Helm Interactive Canvas", content)
        self.assertIn("loadArtifact", content)
        self.assertIn("canvasBadge", content)
        self.assertIn("canvasTitle", content)
        self.assertIn("canvasBody", content)
        self.assertIn("closeCanvas", content)

    def test_helm_api_canvas_message_handling(self):
        """Verifies pywebview JS bridge HelmApi routes open_canvas and toggle_canvas messages."""
        mock_app = MagicMock()
        api = app.HelmApi(mock_app)

        # 1. toggle_canvas message
        api.post({"toggle_canvas": True})
        mock_app.toggle_canvas.assert_called_once()

        # 2. open_canvas message with payload dict
        api.post({
            "open_canvas": {
                "title": "Quick Graph",
                "content": "graph TD; A-->B",
                "type": "mermaid",
            }
        })
        mock_app.show_artifact_on_canvas.assert_called_once_with(
            title="Quick Graph",
            content="graph TD; A-->B",
            content_type="mermaid",
        )

    def test_fast_command_canvas(self):
        """Verifies fast local commands for canvas ('canvas', 'open canvas', 'close canvas')."""
        handled, msg = helm.try_fast_command("canvas")
        self.assertTrue(handled)
        self.assertIn("Side Canvas", msg)

        handled, msg = helm.try_fast_command("open canvas")
        self.assertTrue(handled)
        self.assertIn("Side Canvas", msg)

        handled, msg = helm.try_fast_command("close canvas")
        self.assertTrue(handled)
        self.assertIn("hidden", msg)


if __name__ == "__main__":
    unittest.main()
