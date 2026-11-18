"""homie_omnibar.py - Fast Floating Omnibar (Raycast / Spotlight UX for Windows).

Provides an instant-response (< 5ms) command launcher and OS-indexed search:
- Global Hotkey: Alt + Space toggles floating bar centered on active monitor.
- OS Start Menu Indexer: Resolves .lnk shortcuts across AppData and ProgramData.
- Open Windows Indexer: Enumerates live visible windows for instant task-switching.
- RapidFuzz Matcher: High-precision fuzzy search across apps, open windows, and actions.
- Smooth Windows 11 Fluent Acrylic / Mica aesthetic with Segoe UI Variable typography.
"""

from __future__ import annotations

import os
import sys
import json
import time
import threading
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("homie.omnibar")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OMNIBAR_HTML_PATH = os.path.join(BASE_DIR, "ui", "omnibar.html")

DEFAULT_ACTIONS: List[Dict[str, Any]] = [
    {
        "id": "focus_report",
        "name": "Productivity Focus Report",
        "title": "Productivity Focus Report",
        "subtitle": "View 24h application screen-time summary",
        "icon": "📊",
        "shortcut": "F",
        "type": "action",
    },
    {
        "id": "screen_vision",
        "name": "Analyze Screen Content",
        "title": "Analyze Screen Content",
        "subtitle": "Multimodal vision inspection of current displays",
        "icon": "👀",
        "shortcut": "S",
        "type": "action",
    },
    {
        "id": "make_document",
        "name": "New Word Document (.docx)",
        "title": "New Word Document (.docx)",
        "subtitle": "Generate professional document with safe layout",
        "icon": "📝",
        "shortcut": "D",
        "type": "action",
    },
    {
        "id": "make_presentation",
        "name": "New Presentation (.pptx)",
        "title": "New Presentation (.pptx)",
        "subtitle": "Create 16:9 widescreen PowerPoint deck",
        "icon": "📽️",
        "shortcut": "P",
        "type": "action",
    },
    {
        "id": "make_spreadsheet",
        "name": "New Spreadsheet (.xlsx)",
        "title": "New Spreadsheet (.xlsx)",
        "subtitle": "Generate Excel workbook with formula defense",
        "icon": "📈",
        "shortcut": "X",
        "type": "action",
    },
    {
        "id": "meeting_notes",
        "name": "Meeting Audio Loopback",
        "title": "Meeting Audio Loopback",
        "subtitle": "Live WASAPI transcription & action items",
        "icon": "🎙️",
        "shortcut": "M",
        "type": "action",
    },
    {
        "id": "snap_left",
        "name": "Snap Active Window Left",
        "title": "Snap Active Window Left",
        "subtitle": "Place foreground application on left half",
        "icon": "🪟",
        "shortcut": "←",
        "type": "action",
    },
    {
        "id": "snap_right",
        "name": "Snap Active Window Right",
        "title": "Snap Active Window Right",
        "subtitle": "Place foreground application on right half",
        "icon": "🪟",
        "shortcut": "→",
        "type": "action",
    },
    {
        "id": "list_apps",
        "name": "Browse Connected SaaS Catalog",
        "title": "Browse Connected SaaS Catalog",
        "subtitle": "Explore 65+ MCP apps and SaaS tools",
        "icon": "🔌",
        "shortcut": "A",
        "type": "action",
    },
    {
        "id": "vitals",
        "name": "System Workstation Vitals",
        "title": "System Workstation Vitals",
        "subtitle": "Inspect CPU, RAM, Battery, and Uptime",
        "icon": "💻",
        "shortcut": "V",
        "type": "action",
    },
]


class OmnibarIndexer:
    """Indexes Start Menu applications and running windows for fast fuzzy search."""

    def __init__(self) -> None:
        self._cached_apps: List[Dict[str, Any]] = []
        self._cache_lock = threading.Lock()
        self._last_index_time: float = 0.0
        self._results_cache: Dict[str, Dict[str, Any]] = {}
        # Pre-seed cache with default actions
        for act in DEFAULT_ACTIONS:
            self._results_cache[act["id"]] = dict(act)

    def index_start_menu(self, force: bool = False) -> List[Dict[str, Any]]:
        """Walk %APPDATA%\\Microsoft\\Windows\\Start Menu and %ProgramData%\\Microsoft\\Windows\\Start Menu

        collecting all .lnk files. Resolves targets with WScript.Shell and caches
        results as [{name, path, icon}].
        """
        now = time.time()
        if not force and self._cached_apps and (now - self._last_index_time < 300.0):
            return list(self._cached_apps)

        with self._cache_lock:
            if not force and self._cached_apps and (now - self._last_index_time < 300.0):
                return list(self._cached_apps)

            start_dirs = [
                os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu"),
                os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu"),
            ]

            shell = None
            try:
                import win32com.client
                try:
                    import pythoncom
                    pythoncom.CoInitialize()
                except Exception:
                    pass
                shell = win32com.client.Dispatch("WScript.Shell")
            except Exception as e:
                logger.debug("WScript.Shell unavailable: %s", e)

            indexed_apps: List[Dict[str, Any]] = []
            seen_keys = set()

            for sdir in start_dirs:
                if not os.path.exists(sdir):
                    continue
                for root, _, files in os.walk(sdir):
                    for file in files:
                        if file.lower().endswith(".lnk"):
                            full_lnk = os.path.join(root, file)
                            app_name = os.path.splitext(file)[0]
                            target_path = full_lnk
                            if shell is not None:
                                try:
                                    sc = shell.CreateShortcut(full_lnk)
                                    if sc and sc.TargetPath:
                                        target_path = sc.TargetPath
                                except Exception:
                                    target_path = full_lnk

                            effective_path = target_path or full_lnk
                            dedup_key = (app_name.lower(), effective_path.lower())
                            if dedup_key in seen_keys:
                                continue
                            seen_keys.add(dedup_key)

                            item = {
                                "id": f"app:{effective_path}",
                                "type": "app",
                                "name": app_name,
                                "title": app_name,
                                "path": effective_path,
                                "subtitle": effective_path,
                                "icon": "🚀",
                            }
                            indexed_apps.append(item)
                            self._results_cache[item["id"]] = item

            self._cached_apps = indexed_apps
            self._last_index_time = time.time()
            logger.info("Indexed %d Start Menu applications", len(indexed_apps))
            return list(self._cached_apps)

    def index_running_windows(self) -> List[Dict[str, Any]]:
        """List all visible top-level windows with their titles and PIDs using win32gui.EnumWindows."""
        windows: List[Dict[str, Any]] = []
        try:
            import win32gui
            import win32process

            def enum_cb(hwnd: int, _extra: Any) -> None:
                try:
                    if win32gui.IsWindowVisible(hwnd):
                        title = win32gui.GetWindowText(hwnd).strip()
                        if title:
                            try:
                                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                            except Exception:
                                pid = 0
                            item = {
                                "id": f"win:{hwnd}",
                                "type": "window",
                                "name": title,
                                "title": title,
                                "path": "",
                                "hwnd": hwnd,
                                "pid": pid,
                                "subtitle": f"Switch to window (PID: {pid})" if pid else "Switch to window",
                                "icon": "🪟",
                            }
                            windows.append(item)
                            self._results_cache[item["id"]] = item
                except Exception:
                    pass

            win32gui.EnumWindows(enum_cb, None)
        except Exception as e:
            logger.debug("Error enumerating windows: %s", e)
        return windows

    def search_index(self, query: str) -> List[Dict[str, Any]]:
        """Fuzzy-matches query against app names and window titles using rapidfuzz.fuzz.WRatio.

        Returns top-10 results sorted by score. Falls back to DEFAULT_ACTIONS when query is empty.
        """
        trimmed = (query or "").strip()
        if not trimmed:
            return list(DEFAULT_ACTIONS)

        try:
            from rapidfuzz import fuzz

            def _score(q: str, target: str) -> float:
                return float(fuzz.WRatio(q, target))
        except ImportError:
            def _score(q: str, target: str) -> float:
                ql = q.lower()
                tl = target.lower()
                if ql == tl:
                    return 100.0
                if ql in tl:
                    return 80.0
                matches = sum(1 for c in ql if c in tl)
                return (matches / max(len(ql), 1)) * 50.0

        apps = self.index_start_menu()
        windows = self.index_running_windows()

        candidates: List[Dict[str, Any]] = []
        candidates.extend(windows)
        candidates.extend(apps)
        candidates.extend(DEFAULT_ACTIONS)

        scored: List[Dict[str, Any]] = []
        ql = trimmed.lower()

        for itm in candidates:
            name = itm.get("name") or itm.get("title") or ""
            if not name:
                continue

            base = _score(trimmed, name)
            nl = name.lower()
            boost = 0.0
            if nl == ql:
                boost += 40.0
            elif nl.startswith(ql):
                boost += 25.0
            elif ql in nl:
                boost += 15.0

            # Priority for open windows when matching an active task
            if itm.get("type") == "window":
                boost += 5.0

            total_score = base + boost
            if total_score >= 40.0:
                scored_item = dict(itm)
                scored_item["score"] = total_score
                scored.append(scored_item)

        scored.sort(key=lambda x: x["score"], reverse=True)

        # Deduplicate and return top 10
        results: List[Dict[str, Any]] = []
        seen_keys = set()
        for itm in scored:
            key = itm.get("id") or itm.get("path") or itm.get("title")
            if key not in seen_keys:
                seen_keys.add(key)
                results.append(itm)
                if itm.get("id"):
                    self._results_cache[itm["id"]] = itm
                if len(results) == 10:
                    break

        return results

    def launch_result(self, result: Dict[str, Any] | str) -> bool:
        """Launches target: Either os.startfile(path) for apps or win32gui.SetForegroundWindow(hwnd) for windows."""
        if isinstance(result, str):
            result = self._results_cache.get(result, {"id": result})

        if not isinstance(result, dict):
            return False

        res_type = result.get("type", "")

        # Window target
        if res_type == "window" or "hwnd" in result:
            hwnd = result.get("hwnd")
            if hwnd:
                try:
                    import win32gui
                    import win32con
                    if win32gui.IsIconic(hwnd):
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                    else:
                        win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
                    win32gui.SetForegroundWindow(hwnd)
                    return True
                except Exception as e:
                    logger.warning("Failed to focus window hwnd=%s: %s", hwnd, e)
                    return False

        # App target
        target_path = result.get("path")
        if target_path and (res_type == "app" or not res_type or res_type == "action"):
            try:
                os.startfile(target_path)
                return True
            except Exception as e:
                logger.warning("Failed to startfile %s: %s", target_path, e)
                return False

        return False


_GLOBAL_INDEXER: Optional[OmnibarIndexer] = None


def get_indexer() -> OmnibarIndexer:
    global _GLOBAL_INDEXER
    if _GLOBAL_INDEXER is None:
        _GLOBAL_INDEXER = OmnibarIndexer()
    return _GLOBAL_INDEXER


def index_start_menu(force: bool = False) -> List[Dict[str, Any]]:
    return get_indexer().index_start_menu(force=force)


def index_running_windows() -> List[Dict[str, Any]]:
    return get_indexer().index_running_windows()


def search_index(query: str) -> List[Dict[str, Any]]:
    return get_indexer().search_index(query)


def launch_result(result: Dict[str, Any] | str) -> bool:
    return get_indexer().launch_result(result)


class OmnibarController:
    def __init__(
        self,
        action_handler: Optional[Callable[[str, Any], Any]] = None,
        on_submit: Optional[Callable[[str], Any]] = None,
        indexer: Optional[OmnibarIndexer] = None,
    ):
        self.action_handler = action_handler
        self.on_submit = on_submit
        self.indexer = indexer or get_indexer()
        self.window = None
        self._is_visible = False
        self._lock = threading.Lock()

    def search_omnibar(self, query: str) -> List[Dict[str, Any]]:
        """Invoked from JS pywebview API to return dynamically matched items."""
        return self.indexer.search_index(query)

    def launch_omnibar_result(self, result_id_or_dict: Any) -> bool:
        """Invoked from JS pywebview API when user selects an item via Enter or click."""
        self.hide()
        if isinstance(result_id_or_dict, dict):
            item = result_id_or_dict
        elif isinstance(result_id_or_dict, str):
            item = self.indexer._results_cache.get(result_id_or_dict, {"id": result_id_or_dict})
        else:
            return False

        act_id = item.get("id")
        res_type = item.get("type", "")

        # Check agent_ask
        if act_id == "agent_ask":
            q = item.get("query", "")
            if self.on_submit:
                self.on_submit(q)
            elif self.action_handler:
                self.action_handler("agent_ask", {"query": q})
            else:
                import homie
                homie.try_fast_command(q)
            return True

        # Check calc copy
        if act_id == "calc" or res_type == "calc":
            val = str(item.get("value", ""))
            try:
                import pyperclip
                pyperclip.copy(val)
                return True
            except Exception:
                pass

        # Check window or app launch
        if res_type in ("window", "app") or "hwnd" in item or "path" in item:
            launched = self.indexer.launch_result(item)
            if launched:
                return True

        # Check custom action
        if act_id:
            self.handle_action(act_id, item)
            return True

        return False

    def create_window(self, webview_module=None):
        """Creates the pywebview frameless window centered on screen."""
        if not webview_module:
            try:
                import webview
                webview_module = webview
            except ImportError:
                logger.warning("pywebview not installed; Omnibar window creation deferred.")
                return None

        with self._lock:
            if self.window is not None:
                return self.window

            class OmnibarApi:
                def __init__(self, controller: OmnibarController):
                    self.controller = controller

                def post(self, msg: Any) -> None:
                    if not isinstance(msg, dict):
                        return
                    if msg.get("omnibar_close"):
                        self.controller.hide()
                    elif "omnibar_action" in msg:
                        act = msg.get("omnibar_action")
                        payload = msg.get("payload", {})
                        self.controller.handle_action(act, payload)

                def search_omnibar(self, query: str) -> List[Dict[str, Any]]:
                    return self.controller.search_omnibar(query)

                def launch_omnibar_result(self, result_id: Any) -> bool:
                    return self.controller.launch_omnibar_result(result_id)

            self.api = OmnibarApi(self)
            self.window = webview_module.create_window(
                "Homie Omnibar",
                url=OMNIBAR_HTML_PATH,
                js_api=self.api,
                width=660,
                height=420,
                frameless=True,
                easy_drag=True,
                on_top=True,
                transparent=True,
                background_color="#00000000",
                hidden=True,
            )
            return self.window

    def toggle(self):
        """Toggles Omnibar visibility."""
        if self._is_visible:
            self.hide()
        else:
            self.show()

    def show(self):
        """Presents the Omnibar front and center."""
        if not self.window:
            self.create_window()
        if self.window:
            try:
                self.window.show()
                self.window.restore()
                self._is_visible = True
            except Exception as e:
                logger.debug("Error showing omnibar window: %s", e)

    def hide(self):
        """Hides the Omnibar."""
        if self.window:
            try:
                self.window.hide()
                self._is_visible = False
            except Exception as e:
                logger.debug("Error hiding omnibar window: %s", e)

    def submit(self, query: str):
        """Directly dispatch a query to the on_submit handler."""
        if self.on_submit:
            self.on_submit(query)

    def handle_action(self, action_id: str, payload: dict[str, Any]):
        """Dispatches action to Homie runtime."""
        self.hide()
        logger.info("Omnibar executing action: %s", action_id)

        if action_id == "agent_ask" and self.on_submit:
            q = payload.get("query", "")
            if q:
                self.on_submit(q)
                return

        if self.action_handler:
            self.action_handler(action_id, payload)
        else:
            # Default dispatch to homie
            import homie
            if action_id == "focus_report":
                homie.try_fast_command("focus report")
            elif action_id == "screen_vision":
                import windows_tools
                windows_tools.capture_screens()
            elif action_id == "snap_left":
                import windows_tools
                windows_tools.place_window("foreground", "left")
            elif action_id == "snap_right":
                import windows_tools
                windows_tools.place_window("foreground", "right")
            elif action_id == "calc":
                val = payload.get("value", "")
                try:
                    import pyperclip
                    pyperclip.copy(val)
                except Exception:
                    pass
            elif action_id == "agent_ask":
                q = payload.get("query", "")
                if q:
                    if self.on_submit:
                        self.on_submit(q)
                    else:
                        homie.try_fast_command(q)


_GLOBAL_OMNIBAR: Optional[OmnibarController] = None


def get_omnibar() -> OmnibarController:
    global _GLOBAL_OMNIBAR
    if _GLOBAL_OMNIBAR is None:
        _GLOBAL_OMNIBAR = OmnibarController()
    return _GLOBAL_OMNIBAR


HomieOmnibar = OmnibarController

__all__ = [
    "OmnibarController",
    "HomieOmnibar",
    "get_omnibar",
    "OmnibarIndexer",
    "get_indexer",
    "index_start_menu",
    "index_running_windows",
    "search_index",
    "launch_result",
    "DEFAULT_ACTIONS",
]
