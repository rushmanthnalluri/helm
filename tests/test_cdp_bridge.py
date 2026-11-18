"""Unit tests for Chrome DevTools Protocol (CDP) browser bridge and agent tools."""

import base64
import json
import unittest
from unittest.mock import MagicMock, Mock, patch

import agent_tools
import homie_cdp
from homie_cdp import CDPBridge, launch_chrome_debug


class FakeWebSocket:
    """Mock WebSocket for CDP testing that matches response IDs."""

    def __init__(self, responses=None):
        self.sent_messages = []
        self.responses = responses or {}
        self.closed = False

    def send(self, msg_str):
        data = json.loads(msg_str)
        self.sent_messages.append(data)

    def recv(self):
        if not self.sent_messages:
            return json.dumps({"method": "Page.loadEventFired", "params": {}})
        last_sent = self.sent_messages[-1]
        msg_id = last_sent["id"]
        method = last_sent["method"]

        # Default or configured response
        res_data = self.responses.get(method, {})
        return json.dumps({"id": msg_id, "result": res_data})

    def close(self):
        self.closed = True


class TestCDPBridge(unittest.TestCase):
    def setUp(self):
        self.bridge = CDPBridge()

    def test_connect_success(self):
        """Verify connect parses /json and opens WebSocket to active page tab."""
        fake_tabs = [
            {"id": "tab1", "type": "background_page", "title": "Extension"},
            {"id": "tab2", "type": "page", "title": "Google Docs", "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/tab2"},
        ]

        mock_resp = MagicMock()
        mock_resp.json.return_value = fake_tabs

        fake_ws = FakeWebSocket()

        with patch("requests.get", return_value=mock_resp), \
             patch("websocket.create_connection", return_value=fake_ws):
            ok = self.bridge.connect(port=9222)
            self.assertTrue(ok)
            self.assertTrue(self.bridge.is_connected)
            self.assertEqual(self.bridge.ws_url, "ws://127.0.0.1:9222/devtools/page/tab2")

            # Check that DOM, Page, and Runtime were enabled
            methods_sent = [m["method"] for m in fake_ws.sent_messages]
            self.assertIn("DOM.enable", methods_sent)
            self.assertIn("Page.enable", methods_sent)
            self.assertIn("Runtime.enable", methods_sent)

    def test_connect_no_tabs_raises_connection_error(self):
        """Verify connect raises ConnectionError if no tabs exist."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = []

        with patch("requests.get", return_value=mock_resp):
            with self.assertRaises(ConnectionError):
                self.bridge.connect(port=9222)

    def test_query_selector_found_and_not_found(self):
        """Verify query_selector returns node info or None."""
        responses = {
            "DOM.enable": {},
            "Page.enable": {},
            "Runtime.enable": {},
            "DOM.getDocument": {"root": {"nodeId": 1}},
            "DOM.querySelector": {"nodeId": 42},
            "DOM.describeNode": {"node": {"nodeId": 42, "nodeName": "BUTTON", "attributes": ["id", "submit"]}},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        node = self.bridge.query_selector("#submit")
        self.assertIsNotNone(node)
        self.assertEqual(node["nodeId"], 42)
        self.assertEqual(node["nodeName"], "BUTTON")

        # Not found case
        responses["DOM.querySelector"] = {"nodeId": 0}
        node_missing = self.bridge.query_selector("#nonexistent")
        self.assertIsNone(node_missing)

    def test_query_selector_all(self):
        """Verify query_selector_all returns list of matching node dicts."""
        responses = {
            "DOM.getDocument": {"root": {"nodeId": 1}},
            "DOM.querySelectorAll": {"nodeIds": [10, 20]},
            "DOM.describeNode": {"node": {"nodeName": "DIV"}},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        nodes = self.bridge.query_selector_all(".item")
        self.assertEqual(len(nodes), 2)

    def test_click_element(self):
        """Verify click_element calculates box center and sends mousedown/mouseup."""
        # Quad corners: top-left (10, 20), top-right (50, 20), bottom-right (50, 60), bottom-left (10, 60)
        # Center = ((10+50+50+10)/4, (20+20+60+60)/4) = (30.0, 40.0)
        responses = {
            "DOM.getDocument": {"root": {"nodeId": 1}},
            "DOM.querySelector": {"nodeId": 99},
            "DOM.getBoxModel": {"model": {"content": [10, 20, 50, 20, 50, 60, 10, 60]}},
            "Input.dispatchMouseEvent": {},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        res = self.bridge.click_element("#save-btn")
        self.assertTrue(res["ok"])
        self.assertEqual(res["x"], 30.0)
        self.assertEqual(res["y"], 40.0)

        mouse_events = [m for m in fake_ws.sent_messages if m["method"] == "Input.dispatchMouseEvent"]
        self.assertEqual(len(mouse_events), 2)
        self.assertEqual(mouse_events[0]["params"]["type"], "mousePressed")
        self.assertEqual(mouse_events[0]["params"]["x"], 30.0)
        self.assertEqual(mouse_events[0]["params"]["y"], 40.0)
        self.assertEqual(mouse_events[1]["params"]["type"], "mouseReleased")

    def test_type_text(self):
        """Verify type_text focuses element and sends key events for each character."""
        responses = {
            "Runtime.evaluate": {"result": {"type": "undefined"}},
            "Input.dispatchKeyEvent": {},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        ok = self.bridge.type_text("#input-box", "Hi!")
        self.assertTrue(ok)

        # 1 focus eval + 3 chars * 2 (keyDown + keyUp) = 6 key events
        key_events = [m for m in fake_ws.sent_messages if m["method"] == "Input.dispatchKeyEvent"]
        self.assertEqual(len(key_events), 6)
        typed_chars = [k["params"]["text"] for k in key_events if k["params"]["type"] == "keyDown"]
        self.assertEqual(typed_chars, ["H", "i", "!"])

    def test_evaluate_js(self):
        """Verify evaluate returns value and handles exceptions."""
        responses = {
            "Runtime.evaluate": {"result": {"type": "number", "value": 42}},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        val = self.bridge.evaluate("21 * 2")
        self.assertEqual(val, 42)

        # Exception handling
        responses["Runtime.evaluate"] = {
            "result": {},
            "exceptionDetails": {"text": "ReferenceError: foo is not defined"},
        }
        with self.assertRaisesRegex(RuntimeError, "ReferenceError"):
            self.bridge.evaluate("foo.bar()")

    def test_get_page_text(self):
        """Verify get_page_text queries document.body.innerText."""
        responses = {
            "Runtime.evaluate": {"result": {"type": "string", "value": "Welcome to Homie Workstation"}},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        text = self.bridge.get_page_text()
        self.assertEqual(text, "Welcome to Homie Workstation")

    def test_screenshot(self):
        """Verify screenshot decodes base64 payload from Page.captureScreenshot."""
        sample_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        b64_str = base64.b64encode(sample_bytes).decode("utf-8")
        responses = {
            "Page.captureScreenshot": {"data": b64_str},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        shot = self.bridge.screenshot()
        self.assertEqual(shot, sample_bytes)

    def test_navigate(self):
        """Verify navigate calls Page.navigate."""
        responses = {
            "Page.navigate": {"frameId": "F123"},
        }
        fake_ws = FakeWebSocket(responses=responses)
        self.bridge._ws = fake_ws

        res = self.bridge.navigate("https://notion.so")
        self.assertEqual(res["frameId"], "F123")

    def test_launch_chrome_debug(self):
        """Verify launch_chrome_debug launches browser with remote-debugging-port."""
        with patch("os.path.exists", return_value=True), \
             patch("subprocess.Popen") as mock_popen:
            port = launch_chrome_debug("https://example.com", port=9222)
            self.assertEqual(port, 9222)
            mock_popen.assert_called_once()
            args = mock_popen.call_args[0][0]
            self.assertIn("--remote-debugging-port=9222", args)
            self.assertIn("--no-first-run", args)
            self.assertIn("--no-default-browser-check", args)
            self.assertIn("https://example.com", args)


class TestAgentToolsCDPIntegration(unittest.TestCase):
    def setUp(self):
        self.mock_bridge = MagicMock(spec=CDPBridge)
        self.mock_bridge.is_connected = True
        agent_tools.set_cdp_bridge(self.mock_bridge)

    def tearDown(self):
        agent_tools.set_cdp_bridge(None)

    def test_browser_callable_tools(self):
        """Verify standalone callable tools in agent_tools.py dispatch to CDPBridge."""
        self.mock_bridge.navigate.return_value = {"frameId": "1"}
        self.mock_bridge.click_element.return_value = {"ok": True}
        self.mock_bridge.type_text.return_value = True
        self.mock_bridge.evaluate.return_value = 100
        self.mock_bridge.get_page_text.return_value = "Page content"
        self.mock_bridge.screenshot.return_value = b"fakepng"

        res_nav = agent_tools.browser_navigate("https://jira.atlassian.com")
        self.assertTrue(res_nav["ok"])
        self.mock_bridge.navigate.assert_called_once_with("https://jira.atlassian.com")

        res_click = agent_tools.browser_click("#create-issue")
        self.assertTrue(res_click["ok"])
        self.mock_bridge.click_element.assert_called_once_with("#create-issue")

        res_type = agent_tools.browser_type("#summary", "Fix login bug")
        self.assertTrue(res_type["ok"])
        self.mock_bridge.type_text.assert_called_once_with("#summary", "Fix login bug")

        res_eval = agent_tools.browser_evaluate("window.location.href")
        self.assertEqual(res_eval["data"], 100)
        self.mock_bridge.evaluate.assert_called_once_with("window.location.href")

        res_text = agent_tools.browser_get_text()
        self.assertEqual(res_text["data"], "Page content")

        res_shot = agent_tools.browser_screenshot()
        self.assertTrue(res_shot["ok"])
        self.assertIsInstance(res_shot["data"], str)

    def test_registry_has_browser_tools(self):
        """Verify tools are registered in default and full registries."""
        default_reg = agent_tools.build_default_registry()
        self.assertIn("browser_get_text", default_reg._tools)
        self.assertIn("browser_screenshot", default_reg._tools)

        full_reg = agent_tools.build_full_registry()
        expected = [
            "browser_navigate",
            "browser_click",
            "browser_type",
            "browser_evaluate",
            "browser_get_text",
            "browser_screenshot",
        ]
        for name in expected:
            self.assertIn(name, full_reg._tools)


if __name__ == "__main__":
    unittest.main()
