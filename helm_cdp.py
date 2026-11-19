"""helm_cdp.py - Chrome DevTools Protocol (CDP) Browser Automation Bridge.

Provides modern web application automation (DOM inspection, clicks, typing, JS evaluation,
page text, and screenshots) via standard WebSocket CDP connections to Chrome / Edge.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.cdp")


class CDPBridge:
    """Bridge for automating browsers via Chrome DevTools Protocol (CDP)."""

    def __init__(self) -> None:
        self.port: Optional[int] = None
        self.ws_url: Optional[str] = None
        self.target_tab: Optional[Dict[str, Any]] = None
        self._ws: Any = None
        self._msg_id = 0
        self._lock = threading.Lock()

    @property
    def is_connected(self) -> bool:
        return self._ws is not None

    def connect(self, port: int = 9222, timeout: float = 5.0) -> bool:
        """Connects to Chrome debug port, enumerates tabs via GET /json,

        and opens a WebSocket to the first active page tab.
        """
        import requests
        import websocket

        self.close()
        self.port = port
        json_url = f"http://127.0.0.1:{port}/json"

        try:
            resp = requests.get(json_url, timeout=timeout)
            resp.raise_for_status()
            tabs = resp.json()
        except Exception as e:
            raise ConnectionError(f"Could not reach Chrome debug port at {json_url}: {e}")

        target_tab = None
        for tab in tabs:
            if tab.get("type") == "page" and "webSocketDebuggerUrl" in tab:
                target_tab = tab
                break

        if not target_tab:
            for tab in tabs:
                if "webSocketDebuggerUrl" in tab:
                    target_tab = tab
                    break

        if not target_tab:
            raise ConnectionError(f"No active debuggable tabs found on port {port}")

        self.ws_url = target_tab["webSocketDebuggerUrl"]
        self.target_tab = target_tab
        self._ws = websocket.create_connection(self.ws_url, timeout=timeout)

        # Enable core domains
        self.send_command("DOM.enable")
        self.send_command("Page.enable")
        self.send_command("Runtime.enable")
        logger.info("Connected to CDP tab: %s (%s)", target_tab.get("title", ""), self.ws_url)
        return True

    def close(self) -> None:
        """Closes the WebSocket connection."""
        with self._lock:
            if self._ws:
                try:
                    self._ws.close()
                except Exception:
                    pass
                self._ws = None
            self.target_tab = None
            self.ws_url = None

    def send_command(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """Sends a JSON-RPC command over CDP WebSocket and waits for matching response."""
        with self._lock:
            if not self._ws:
                raise ConnectionError("Not connected to CDP WebSocket")
            self._msg_id += 1
            msg_id = self._msg_id
            payload = {
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
            self._ws.send(json.dumps(payload))

            start_time = time.time()
            while time.time() - start_time < timeout:
                raw = self._ws.recv()
                if not raw:
                    continue
                data = json.loads(raw)
                if data.get("id") == msg_id:
                    if "error" in data:
                        raise RuntimeError(f"CDP error in {method}: {data['error']}")
                    return data.get("result", {})

            raise TimeoutError(f"CDP command {method} (id={msg_id}) timed out after {timeout}s")

    def navigate(self, url: str) -> Dict[str, Any]:
        """Navigates current tab to given URL."""
        return self.send_command("Page.navigate", {"url": url})

    def query_selector(self, selector: str) -> Optional[Dict[str, Any]]:
        """Queries a single element by CSS selector and returns node info."""
        doc = self.send_command("DOM.getDocument")
        root_node_id = doc.get("root", {}).get("nodeId", 1)
        res = self.send_command("DOM.querySelector", {"nodeId": root_node_id, "selector": selector})
        node_id = res.get("nodeId")
        if not node_id:
            return None
        node_info = self.send_command("DOM.describeNode", {"nodeId": node_id})
        return node_info.get("node", {"nodeId": node_id})

    def query_selector_all(self, selector: str) -> List[Dict[str, Any]]:
        """Queries all matching elements by CSS selector and returns their node info."""
        doc = self.send_command("DOM.getDocument")
        root_node_id = doc.get("root", {}).get("nodeId", 1)
        res = self.send_command("DOM.querySelectorAll", {"nodeId": root_node_id, "selector": selector})
        node_ids = res.get("nodeIds", [])
        nodes = []
        for nid in node_ids:
            node_info = self.send_command("DOM.describeNode", {"nodeId": nid})
            nodes.append(node_info.get("node", {"nodeId": nid}))
        return nodes

    def click_element(self, selector: str) -> Dict[str, Any]:
        """Resolves element center via DOM.getBoxModel, then dispatches mouse click events."""
        doc = self.send_command("DOM.getDocument")
        root_node_id = doc.get("root", {}).get("nodeId", 1)
        res = self.send_command("DOM.querySelector", {"nodeId": root_node_id, "selector": selector})
        node_id = res.get("nodeId")
        if not node_id:
            raise ValueError(f"Element not found for selector: {selector}")

        box_res = self.send_command("DOM.getBoxModel", {"nodeId": node_id})
        model = box_res.get("model", {})
        content = model.get("content")
        if not content or len(content) < 8:
            raise ValueError(f"Invalid box model returned for selector: {selector}")

        center_x = (content[0] + content[2] + content[4] + content[6]) / 4.0
        center_y = (content[1] + content[3] + content[5] + content[7]) / 4.0

        self.send_command(
            "Input.dispatchMouseEvent",
            {"type": "mousePressed", "x": center_x, "y": center_y, "button": "left", "clickCount": 1},
        )
        self.send_command(
            "Input.dispatchMouseEvent",
            {"type": "mouseReleased", "x": center_x, "y": center_y, "button": "left", "clickCount": 1},
        )
        return {"ok": True, "x": center_x, "y": center_y, "selector": selector}

    def type_text(self, selector: str, text: str) -> bool:
        """Focuses element via Runtime.evaluate, then dispatches key events for each character."""
        focus_expr = f"document.querySelector({json.dumps(selector)}).focus()"
        self.evaluate(focus_expr)

        for char in text:
            self.send_command(
                "Input.dispatchKeyEvent",
                {"type": "keyDown", "text": char, "unmodifiedText": char},
            )
            self.send_command(
                "Input.dispatchKeyEvent",
                {"type": "keyUp"},
            )
        return True

    def evaluate(self, expression: str) -> Any:
        """Evaluates JavaScript expression in the page and returns the result."""
        res = self.send_command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        if "exceptionDetails" in res:
            details = res["exceptionDetails"]
            msg = details.get("exception", {}).get("description") or details.get("text", "JS Exception")
            raise RuntimeError(f"CDP evaluation error: {msg}")
        result_obj = res.get("result", {})
        return result_obj.get("value")

    def get_page_text(self) -> str:
        """Returns document.body.innerText."""
        res = self.evaluate("document.body.innerText")
        return str(res or "")

    def screenshot(self) -> bytes:
        """Captures page screenshot as PNG bytes."""
        res = self.send_command("Page.captureScreenshot", {"format": "png"})
        data_b64 = res.get("data", "")
        return base64.b64decode(data_b64)


def launch_chrome_debug(url: str = "about:blank", port: int = 9222) -> int:
    """Launches Chrome or Edge with --remote-debugging-port=<port> --no-first-run --no-default-browser-check

    via subprocess.Popen and returns the port.
    """
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ]

    browser_exe = None
    for path in candidates:
        if os.path.exists(path):
            browser_exe = path
            break

    if not browser_exe:
        for bin_name in ["chrome", "google-chrome", "msedge", "chromium"]:
            found = shutil.which(bin_name)
            if found:
                browser_exe = found
                break

    if not browser_exe:
        raise FileNotFoundError("Could not find Chrome, Edge, or Chromium executable on system")

    args = [
        browser_exe,
        f"--remote-debugging-port={port}",
        "--no-first-run",
        "--no-default-browser-check",
        url,
    ]
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return port


__all__ = ["CDPBridge", "launch_chrome_debug"]
