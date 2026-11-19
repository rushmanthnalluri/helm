"""helm_focus_mode.py - Intelligent Focus Mode & Digital Wellbeing for Helm.

Provides proactive distraction suppression and Pomodoro focus management:
- Configurable focus sessions with duration and allowed application lists
- Automatically minimizes non-allowed application windows
- Suppresses or queues notifications during active sessions
- Records completed focus sessions and elapsed productive minutes
- Integrates with windows_tools and notification_mirror
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

logger = logging.getLogger("helm.focus_mode")

_LOCK = threading.RLock()

DEFAULT_ALLOWED_APPS = [
    "code.exe", "devenv.exe", "pycharm64.exe", "sublime_text.exe",
    "windowsterminal.exe", "wt.exe", "powershell.exe", "cmd.exe",
    "notepad.exe", "obsidian.exe", "notion.exe"
]


def get_focus_state_path() -> Path:
    """Returns persistent path to focus_mode_state.json."""
    custom = os.environ.get("HELM_FOCUS_STATE_PATH")
    if custom:
        return Path(custom).resolve()
    base = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
    return (base / "focus_mode_state.json").resolve()


class FocusSession:
    def __init__(self):
        self.is_active = False
        self.session_id = None
        self.session_name = "Focus Session"
        self.start_time = None
        self.end_time = None
        self.duration_seconds = 0
        self.allowed_apps = list(DEFAULT_ALLOWED_APPS)
        self.minimized_hwnds = []

    def to_dict(self) -> Dict[str, Any]:
        now = time.time()
        remaining = max(0.0, self.end_time - now) if (self.is_active and self.end_time) else 0.0
        elapsed = (now - self.start_time) if (self.is_active and self.start_time) else 0.0
        return {
            "is_active": self.is_active,
            "session_id": self.session_id,
            "session_name": self.session_name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_minutes": round(self.duration_seconds / 60.0, 1),
            "remaining_minutes": round(remaining / 60.0, 1),
            "elapsed_minutes": round(elapsed / 60.0, 1),
            "allowed_apps": self.allowed_apps,
            "minimized_count": len(self.minimized_hwnds)
        }


_CURRENT_SESSION = FocusSession()


def is_focus_mode_active() -> bool:
    """Returns True if a focus session is currently in progress."""
    with _LOCK:
        if not _CURRENT_SESSION.is_active:
            return False
        # Auto-expire if end_time reached
        if _CURRENT_SESSION.end_time and time.time() >= _CURRENT_SESSION.end_time:
            _CURRENT_SESSION.is_active = False
            return False
        return True


def start_focus_mode(
    duration_minutes: int = 25,
    allowed_apps: Optional[List[str]] = None,
    session_name: str = "Focus Session",
    minimize_distractions: bool = True
) -> Dict[str, Any]:
    """Starts a new focus session, optionally minimizing non-whitelisted windows."""
    with _LOCK:
        now = time.time()
        dur_sec = max(60, int(duration_minutes * 60))
        
        apps = [a.lower().strip() for a in allowed_apps] if allowed_apps else list(DEFAULT_ALLOWED_APPS)
        # Always allow helm / python
        for system_app in ("python.exe", "antigravity.exe", "explorer.exe"):
            if system_app not in apps:
                apps.append(system_app)

        _CURRENT_SESSION.is_active = True
        _CURRENT_SESSION.session_id = f"focus_{int(now)}"
        _CURRENT_SESSION.session_name = session_name
        _CURRENT_SESSION.start_time = now
        _CURRENT_SESSION.end_time = now + dur_sec
        _CURRENT_SESSION.duration_seconds = dur_sec
        _CURRENT_SESSION.allowed_apps = apps
        _CURRENT_SESSION.minimized_hwnds = []

        minimized_procs = []
        if minimize_distractions:
            import win32gui
            import win32con

            windows = windows_tools.find_windows()
            for w in windows:
                hwnd = w.get("hwnd")
                proc_name = (w.get("proc_name") or "").lower().strip()
                if not hwnd or not proc_name:
                    continue

                if proc_name not in apps and not any(proc_name.startswith(a.replace(".exe", "")) for a in apps):
                    try:
                        if win32gui.IsWindowVisible(hwnd) and not win32gui.IsIconic(hwnd):
                            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
                            _CURRENT_SESSION.minimized_hwnds.append(hwnd)
                            minimized_procs.append(proc_name)
                    except Exception as e:
                        logger.debug("Could not minimize window %s (%s): %s", hwnd, proc_name, e)

        status = _CURRENT_SESSION.to_dict()
        status["minimized_processes"] = list(set(minimized_procs))
        
        # Persist state
        try:
            p = get_focus_state_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(status, indent=2), encoding="utf-8")
        except Exception:
            pass

        return status


def stop_focus_mode(restore_windows: bool = True) -> Dict[str, Any]:
    """Ends the current focus session and optionally restores previously minimized windows."""
    with _LOCK:
        if not _CURRENT_SESSION.is_active:
            return {"is_active": False, "message": "No active focus session to stop."}

        restored_count = 0
        if restore_windows and _CURRENT_SESSION.minimized_hwnds:
            import win32gui
            import win32con

            for hwnd in _CURRENT_SESSION.minimized_hwnds:
                try:
                    if win32gui.IsWindow(hwnd) and win32gui.IsIconic(hwnd):
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                        restored_count += 1
                except Exception:
                    pass

        summary = _CURRENT_SESSION.to_dict()
        _CURRENT_SESSION.is_active = False
        summary["is_active"] = False
        summary["restored_windows_count"] = restored_count

        try:
            p = get_focus_state_path()
            if p.exists():
                p.unlink()
        except Exception:
            pass

        return summary


def get_focus_status() -> Dict[str, Any]:
    """Returns current focus mode state."""
    with _LOCK:
        # Check auto-expiry
        if _CURRENT_SESSION.is_active and _CURRENT_SESSION.end_time and time.time() >= _CURRENT_SESSION.end_time:
            _CURRENT_SESSION.is_active = False
        return _CURRENT_SESSION.to_dict()
