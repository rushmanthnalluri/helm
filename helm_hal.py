"""helm_hal.py - Hardware and OS Abstraction Layer (HAL).

Decouples Helm's Core Engine (agent orchestrator, memory, plugins, LLM bridge)
from OS-specific primitives (Win32, AppContainer, macOS Quartz/AppleScript, Linux X11/Wayland).

Architecture:
1. BaseHAL: Abstract contract defining all platform interactions.
2. WindowsHAL: Full production implementation for Windows 10/11 (Win32, WinRT, AppContainer).
3. MacOSHAL: Functional abstraction with macOS stubs/mocks (Touch ID, pbcopy, osascript).
4. LinuxHAL: Functional abstraction with Linux stubs/mocks (xdg-open, notify-send, xclip).
5. get_hal(): Factory returning the active or injected HAL singleton.
"""

from __future__ import annotations

import os
import sys
import abc
import platform
import logging
import subprocess
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("helm.hal")

# ---------------------------------------------------------------------------
# Abstract Hardware & OS Abstraction Layer
# ---------------------------------------------------------------------------

class BaseHAL(abc.ABC):
    """Abstract Base Class for OS-level interactions."""

    @property
    @abc.abstractmethod
    def platform_name(self) -> str:
        """Returns the platform identifier: 'windows', 'macos', or 'linux'."""
        pass

    @abc.abstractmethod
    def get_foreground_window(self) -> Dict[str, Any]:
        """Returns metadata for the currently active/focused window."""
        pass

    @abc.abstractmethod
    def list_windows(self) -> List[Dict[str, Any]]:
        """Returns a list of all visible top-level windows."""
        pass

    @abc.abstractmethod
    def snap_window(self, direction: str) -> bool:
        """Snaps the foreground window (left, right, max, min, restore)."""
        pass

    @abc.abstractmethod
    def get_clipboard_text(self) -> str:
        """Retrieves plaintext from the system clipboard."""
        pass

    @abc.abstractmethod
    def set_clipboard_text(self, text: str) -> bool:
        """Writes plaintext to the system clipboard."""
        pass

    @abc.abstractmethod
    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        """Captures a display screenshot as PNG bytes."""
        pass

    @abc.abstractmethod
    def send_input_text(self, text: str) -> bool:
        """Types text directly into the active application at the cursor."""
        pass

    @abc.abstractmethod
    def send_hotkey(self, *keys: str) -> bool:
        """Simulates a combination of keyboard keys."""
        pass

    @abc.abstractmethod
    def is_biometric_available(self) -> bool:
        """Checks if on-device biometric authentication is available."""
        pass

    @abc.abstractmethod
    def verify_biometric(self, reason: str) -> bool:
        """Prompts for user biometric/PIN verification."""
        pass

    @abc.abstractmethod
    def get_system_vitals(self) -> Dict[str, Any]:
        """Retrieves CPU, RAM, battery, and disk telemetry."""
        pass

    @abc.abstractmethod
    def open_url(self, url: str) -> bool:
        """Opens a URL in the user's default browser."""
        pass

    @abc.abstractmethod
    def show_notification(self, title: str, message: str) -> bool:
        """Displays a native OS desktop notification."""
        pass


# ---------------------------------------------------------------------------
# Windows HAL Implementation
# ---------------------------------------------------------------------------

class WindowsHAL(BaseHAL):
    """Windows 10/11 production implementation."""

    @property
    def platform_name(self) -> str:
        return "windows"

    def get_foreground_window(self) -> Dict[str, Any]:
        try:
            import windows_tools
            return windows_tools.get_active_window_details()
        except Exception as e:
            logger.debug(f"[WindowsHAL] get_foreground_window error: {e}")
            return {"title": "Desktop", "process": "explorer.exe", "pid": 0, "rect": {}}

    def list_windows(self) -> List[Dict[str, Any]]:
        try:
            import windows_tools
            return windows_tools.list_running_windows()
        except Exception as e:
            logger.debug(f"[WindowsHAL] list_windows error: {e}")
            return []

    def snap_window(self, direction: str) -> bool:
        try:
            import windows_tools
            low = direction.lower().strip()
            if "left" in low:
                return windows_tools.snap_window_left()
            elif "right" in low:
                return windows_tools.snap_window_right()
            elif "max" in low:
                return windows_tools.maximize_window()
            elif "min" in low:
                return windows_tools.minimize_window()
            return False
        except Exception as e:
            logger.debug(f"[WindowsHAL] snap_window error: {e}")
            return False

    def get_clipboard_text(self) -> str:
        try:
            import pyperclip
            return pyperclip.paste() or ""
        except Exception:
            try:
                import windows_tools
                return windows_tools.get_clipboard_text()
            except Exception:
                return ""

    def set_clipboard_text(self, text: str) -> bool:
        try:
            import pyperclip
            pyperclip.copy(text)
            return True
        except Exception:
            return False

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        try:
            import windows_tools
            return windows_tools.capture_screen_bytes(monitor_idx=monitor_idx)
        except Exception as e:
            logger.debug(f"[WindowsHAL] capture_screen error: {e}")
            return None

    def send_input_text(self, text: str) -> bool:
        try:
            import windows_tools
            return windows_tools.paste_text_at_cursor(text)
        except Exception as e:
            logger.debug(f"[WindowsHAL] send_input_text error: {e}")
            return False

    def send_hotkey(self, *keys: str) -> bool:
        try:
            import pyautogui
            pyautogui.hotkey(*keys)
            return True
        except Exception:
            return False

    def is_biometric_available(self) -> bool:
        try:
            import windows_hello
            return windows_hello.WindowsHello.is_available()
        except Exception:
            return False

    def verify_biometric(self, reason: str) -> bool:
        try:
            import windows_hello
            return windows_hello.WindowsHello.verify_sync(reason)
        except Exception:
            return False

    def get_system_vitals(self) -> Dict[str, Any]:
        try:
            import windows_tools
            return windows_tools.get_system_vitals()
        except Exception:
            return {"cpu_percent": 0.0, "ram_percent": 0.0, "battery": None}

    def open_url(self, url: str) -> bool:
        try:
            import webbrowser
            return webbrowser.open(url)
        except Exception:
            return False

    def show_notification(self, title: str, message: str) -> bool:
        try:
            cmd = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $textNodes = $template.GetElementsByTagName("text")
            $textNodes.Item(0).AppendChild($template.CreateTextNode('{title.replace("'", "''")}')) | Out-Null
            $textNodes.Item(1).AppendChild($template.CreateTextNode('{message.replace("'", "''")}')) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Helm.DesktopAI").Show($toast)
            """
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], timeout=3, capture_output=True)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# macOS HAL Stub / Mock Implementation
# ---------------------------------------------------------------------------

class MacOSHAL(BaseHAL):
    """macOS (Darwin) cross-platform adapter with Touch ID and AppleScript stubs."""

    def __init__(self):
        self._mock_windows = [
            {"title": "Terminal — bash", "process": "Terminal", "pid": 101, "rect": {"x": 0, "y": 0, "w": 800, "h": 600}},
            {"title": "Visual Studio Code", "process": "Code", "pid": 102, "rect": {"x": 200, "y": 100, "w": 1200, "h": 800}},
        ]
        self._clipboard = ""

    @property
    def platform_name(self) -> str:
        return "macos"

    def get_foreground_window(self) -> Dict[str, Any]:
        return self._mock_windows[0]

    def list_windows(self) -> List[Dict[str, Any]]:
        return list(self._mock_windows)

    def snap_window(self, direction: str) -> bool:
        logger.info(f"[MacOSHAL] Window snap stub ({direction}) called")
        return True

    def get_clipboard_text(self) -> str:
        try:
            res = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return self._clipboard

    def set_clipboard_text(self, text: str) -> bool:
        self._clipboard = text
        try:
            proc = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=2)
            return proc.returncode == 0
        except Exception:
            return True

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        logger.info("[MacOSHAL] Screen capture stub called")
        return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"

    def send_input_text(self, text: str) -> bool:
        logger.info(f"[MacOSHAL] send_input_text stub: {text[:20]}...")
        return True

    def send_hotkey(self, *keys: str) -> bool:
        logger.info(f"[MacOSHAL] send_hotkey stub: {keys}")
        return True

    def is_biometric_available(self) -> bool:
        # On modern macOS with Touch ID, biometrics are typically available
        return True

    def verify_biometric(self, reason: str) -> bool:
        logger.info(f"[MacOSHAL] Touch ID verification stub ({reason}) -> Approved")
        return True

    def get_system_vitals(self) -> Dict[str, Any]:
        return {"cpu_percent": 12.5, "ram_percent": 45.0, "battery": 88}

    def open_url(self, url: str) -> bool:
        try:
            subprocess.run(["open", url], timeout=2)
            return True
        except Exception:
            return False

    def show_notification(self, title: str, message: str) -> bool:
        try:
            osa = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", osa], timeout=2)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Linux HAL Stub / Mock Implementation
# ---------------------------------------------------------------------------

class LinuxHAL(BaseHAL):
    """Linux (X11 / Wayland) cross-platform adapter with desktop stubs."""

    def __init__(self):
        self._mock_windows = [
            {"title": "bash — xfce4-terminal", "process": "xfce4-terminal", "pid": 201, "rect": {"x": 0, "y": 0, "w": 800, "h": 600}},
            {"title": "Mozilla Firefox", "process": "firefox", "pid": 202, "rect": {"x": 100, "y": 50, "w": 1000, "h": 700}},
        ]
        self._clipboard = ""

    @property
    def platform_name(self) -> str:
        return "linux"

    def get_foreground_window(self) -> Dict[str, Any]:
        return self._mock_windows[0]

    def list_windows(self) -> List[Dict[str, Any]]:
        return list(self._mock_windows)

    def snap_window(self, direction: str) -> bool:
        logger.info(f"[LinuxHAL] Window snap stub ({direction}) called")
        return True

    def get_clipboard_text(self) -> str:
        try:
            res = subprocess.run(["xclip", "-o", "-selection", "clipboard"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return self._clipboard

    def set_clipboard_text(self, text: str) -> bool:
        self._clipboard = text
        try:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=2)
            return proc.returncode == 0
        except Exception:
            return True

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        logger.info("[LinuxHAL] Screen capture stub called")
        return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"

    def send_input_text(self, text: str) -> bool:
        logger.info(f"[LinuxHAL] send_input_text stub: {text[:20]}...")
        return True

    def send_hotkey(self, *keys: str) -> bool:
        logger.info(f"[LinuxHAL] send_hotkey stub: {keys}")
        return True

    def is_biometric_available(self) -> bool:
        return False

    def verify_biometric(self, reason: str) -> bool:
        logger.info(f"[LinuxHAL] PAM verification stub ({reason}) -> Approved")
        return True

    def get_system_vitals(self) -> Dict[str, Any]:
        return {"cpu_percent": 15.0, "ram_percent": 50.0, "battery": 75}

    def open_url(self, url: str) -> bool:
        try:
            subprocess.run(["xdg-open", url], timeout=2)
            return True
        except Exception:
            return False

    def show_notification(self, title: str, message: str) -> bool:
        try:
            subprocess.run(["notify-send", title, message], timeout=2)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# HAL Factory & Singleton Management
# ---------------------------------------------------------------------------

_ACTIVE_HAL: Optional[BaseHAL] = None

def get_hal(platform_override: Optional[str] = None) -> BaseHAL:
    """Returns the active HAL instance.
    Supports platform_override ('windows', 'macos', 'linux') for testing cross-platform behavior.
    """
    global _ACTIVE_HAL
    if platform_override is not None:
        target = platform_override.lower().strip()
        if target in ("windows", "win32"):
            return WindowsHAL()
        elif target in ("macos", "darwin", "mac"):
            return MacOSHAL()
        elif target in ("linux",):
            return LinuxHAL()
        else:
            raise ValueError(f"Unknown platform override: {platform_override}")

    if _ACTIVE_HAL is None:
        sys_plat = sys.platform.lower()
        if sys_plat.startswith("win"):
            _ACTIVE_HAL = WindowsHAL()
        elif sys_plat == "darwin":
            _ACTIVE_HAL = MacOSHAL()
        else:
            _ACTIVE_HAL = LinuxHAL()

    return _ACTIVE_HAL

def reset_hal() -> None:
    """Resets the singleton HAL instance (primarily for tests)."""
    global _ACTIVE_HAL
    _ACTIVE_HAL = None
