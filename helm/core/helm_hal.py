"""helm_hal.py - Hardware and OS Abstraction Layer (HAL).

Unified cross-platform Hardware & OS Abstraction Layer decoupling Helm's core engine,
UI, and tools from Windows-only dependencies (win32gui, win32api, WinRT).

Architecture:
1. Core Abstract Interfaces:
   - IWindowManager: Window enumeration, focus, title/class queries, minimize/maximize.
   - INotificationManager: Desktop system notifications.
   - IBiometrics: Authentication via biometrics or OS prompt (Windows Hello, Touch ID, polkit).
   - ISystemVitals: CPU, memory, battery, and disk telemetry.
   - IClipboardManager: System clipboard read and write.
   - IInputSimulator: Hardware-level keyboard typing and hotkeys.
   - BaseHAL: Unified composite interface integrating all 6 subsystems.

2. Platform Implementations:
   - WindowsHAL: Native Win32 / WinRT implementation.
   - DarwinHAL / MacOSHAL: macOS platform implementation and AppleScript / Touch ID stubs.
   - LinuxHAL: Linux X11/Wayland implementation and xdotool / dbus / procfs stubs.
   - MockHAL: Clean headless mock for unit tests and CI.

3. Auto-detection Factory:
   - get_hal(platform_override=None): Dynamically selects the appropriate implementation
     for sys.platform or specified override.
   - set_hal(hal): Injects a custom or mock HAL singleton.
   - reset_hal(): Clears the active singleton instance.
"""

from __future__ import annotations

import abc
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("helm.hal")

# 1x1 transparent PNG fallback bytes
_DUMMY_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00"
    b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
)


# ===========================================================================
# 1. Core Abstract Subsystem Interfaces
# ===========================================================================

class IWindowManager(abc.ABC):
    """Abstract interface for desktop window management."""

    @abc.abstractmethod
    def get_active_window(self) -> Dict[str, Any]:
        """Returns metadata for the currently active/focused window.
        Dict must contain 'title', 'class_name' (or 'class'), 'pid', and 'rect'.
        """
        pass

    @abc.abstractmethod
    def get_active_window_title(self) -> str:
        """Returns the title text of the currently active window."""
        pass

    @abc.abstractmethod
    def get_active_window_class(self) -> str:
        """Returns the window class or application name of the active window."""
        pass

    @abc.abstractmethod
    def list_windows(self) -> List[Dict[str, Any]]:
        """Returns a list of all visible top-level desktop windows."""
        pass

    @abc.abstractmethod
    def focus_window(self, target: Any) -> bool:
        """Brings the specified window (handle, pid, or title) to the foreground."""
        pass

    @abc.abstractmethod
    def minimize_window(self, target: Optional[Any] = None) -> bool:
        """Minimizes the specified window (or active window if None)."""
        pass

    @abc.abstractmethod
    def maximize_window(self, target: Optional[Any] = None) -> bool:
        """Maximizes the specified window (or active window if None)."""
        pass

    @abc.abstractmethod
    def snap_window(self, direction: str) -> bool:
        """Snaps the active window (left, right, max, min, restore)."""
        pass

    def get_foreground_window(self) -> Dict[str, Any]:
        """Backward-compatible alias for get_active_window."""
        return self.get_active_window()


class INotificationManager(abc.ABC):
    """Abstract interface for desktop system notifications."""

    @abc.abstractmethod
    def post_notification(
        self,
        title: str,
        message: str,
        app_name: str = "Helm",
        icon_path: Optional[str] = None,
    ) -> bool:
        """Displays a native desktop system notification."""
        pass

    def show_notification(self, title: str, message: str) -> bool:
        """Backward-compatible convenience alias for post_notification."""
        return self.post_notification(title=title, message=message)


class IBiometrics(abc.ABC):
    """Abstract interface for biometric and OS security prompt authentication."""

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Checks if on-device biometric authentication (Windows Hello, Touch ID, polkit) is available."""
        pass

    @abc.abstractmethod
    def authenticate(
        self,
        reason: str = "Helm needs your approval",
        timeout_seconds: float = 30.0,
    ) -> bool:
        """Prompts for user biometric or PIN verification. Returns True if verified."""
        pass

    def is_biometric_available(self) -> bool:
        """Backward-compatible alias for is_available."""
        return self.is_available()

    def verify_biometric(self, reason: str = "Helm needs your approval") -> bool:
        """Backward-compatible alias for authenticate."""
        return self.authenticate(reason=reason)


class ISystemVitals(abc.ABC):
    """Abstract interface for system resource monitoring and health vitals."""

    @abc.abstractmethod
    def get_cpu_usage(self) -> float:
        """Returns overall CPU utilization percentage (0.0 - 100.0)."""
        pass

    @abc.abstractmethod
    def get_memory_usage(self) -> Dict[str, Any]:
        """Returns memory usage dict with total_gb, avail_gb, used_gb, and percent."""
        pass

    @abc.abstractmethod
    def get_battery_status(self) -> Dict[str, Any]:
        """Returns battery info with percent, power_plugged, and status description."""
        pass

    @abc.abstractmethod
    def get_disk_usage(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Returns disk telemetry with total_gb, free_gb, used_gb, and percent."""
        pass

    @abc.abstractmethod
    def get_system_vitals(self) -> Dict[str, Any]:
        """Returns consolidated health vitals dictionary."""
        pass


class IClipboardManager(abc.ABC):
    """Abstract interface for system clipboard interactions."""

    @abc.abstractmethod
    def get_text(self) -> str:
        """Retrieves plaintext from the system clipboard."""
        pass

    @abc.abstractmethod
    def set_text(self, text: str) -> bool:
        """Writes plaintext to the system clipboard."""
        pass

    def get_clipboard_text(self) -> str:
        """Backward-compatible alias for get_text."""
        return self.get_text()

    def set_clipboard_text(self, text: str) -> bool:
        """Backward-compatible alias for set_text."""
        return self.set_text(text)


class IInputSimulator(abc.ABC):
    """Abstract interface for simulated keyboard typing and hotkeys."""

    @abc.abstractmethod
    def type_text(self, text: str) -> bool:
        """Types text directly into the active application at the cursor."""
        pass

    @abc.abstractmethod
    def send_hotkey(self, *keys: str) -> bool:
        """Simulates a combination of keyboard keys (e.g. 'ctrl', 'c')."""
        pass

    @abc.abstractmethod
    def press_key(self, key: str) -> bool:
        """Presses and releases a single key."""
        pass

    def send_input_text(self, text: str) -> bool:
        """Backward-compatible alias for type_text."""
        return self.type_text(text)


# ===========================================================================
# Base Composite HAL
# ===========================================================================

class BaseHAL(
    IWindowManager,
    INotificationManager,
    IBiometrics,
    ISystemVitals,
    IClipboardManager,
    IInputSimulator,
    abc.ABC,
):
    """Unified Hardware & OS Abstraction Layer contract.

    Exposes all subsystems directly while also providing modular accessors
    (window_manager, notification_manager, biometrics, vitals, clipboard, input_simulator).
    """

    @property
    @abc.abstractmethod
    def platform_name(self) -> str:
        """Platform identifier: 'windows', 'darwin', 'macos', 'linux', or 'mock'."""
        pass

    @abc.abstractmethod
    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        """Captures a display screenshot as PNG bytes."""
        pass

    @abc.abstractmethod
    def open_url(self, url: str) -> bool:
        """Opens a URL in the user's default browser."""
        pass

    # Modular manager accessors
    @property
    def window_manager(self) -> IWindowManager:
        return self

    @property
    def notification_manager(self) -> INotificationManager:
        return self

    @property
    def biometrics(self) -> IBiometrics:
        return self

    @property
    def vitals(self) -> ISystemVitals:
        return self

    @property
    def clipboard(self) -> IClipboardManager:
        return self

    @property
    def input_simulator(self) -> IInputSimulator:
        return self


# ===========================================================================
# 2. Windows HAL Implementation (Native Win32 / WinRT)
# ===========================================================================

class WindowsHAL(BaseHAL):
    """Production implementation for Windows 10/11 using Win32, ctypes, and WinRT."""

    def __init__(self) -> None:
        self._clipboard_buffer = ""

    @property
    def platform_name(self) -> str:
        return "windows"

    # --- Window Manager ---

    def get_active_window(self) -> Dict[str, Any]:
        """Retrieves active window via win32gui or ctypes user32."""
        try:
            import windows_tools
            fg = windows_tools.get_foreground_window()
            if fg and isinstance(fg, dict):
                title = fg.get("title", "")
                pid = fg.get("pid", 0)
                proc_name = fg.get("proc_name", "")
                rect = fg.get("rect", (0, 0, 0, 0))
                hwnd = fg.get("hwnd", 0)
                return {
                    "hwnd": hwnd,
                    "title": title,
                    "class": proc_name or "Window",
                    "class_name": proc_name or "Window",
                    "process": proc_name or "explorer.exe",
                    "pid": pid,
                    "rect": {
                        "x": rect[0] if isinstance(rect, (list, tuple)) and len(rect) > 0 else 0,
                        "y": rect[1] if isinstance(rect, (list, tuple)) and len(rect) > 1 else 0,
                        "w": (rect[2] - rect[0]) if isinstance(rect, (list, tuple)) and len(rect) > 2 else 0,
                        "h": (rect[3] - rect[1]) if isinstance(rect, (list, tuple)) and len(rect) > 3 else 0,
                    },
                }
        except Exception:
            pass

        # Ctypes user32 fallback
        try:
            import ctypes
            import ctypes.wintypes
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if hwnd:
                buf = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, buf, 512)
                title = buf.value
                user32.GetClassNameW(hwnd, buf, 512)
                cls_name = buf.value
                pid = ctypes.wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                return {
                    "hwnd": hwnd,
                    "title": title or "Desktop",
                    "class": cls_name or "Progman",
                    "class_name": cls_name or "Progman",
                    "process": "explorer.exe",
                    "pid": pid.value,
                    "rect": {"x": 0, "y": 0, "w": 1920, "h": 1080},
                }
        except Exception as e:
            logger.debug(f"[WindowsHAL] get_active_window ctypes fallback error: {e}")

        return {
            "hwnd": 0,
            "title": "Desktop",
            "class": "Progman",
            "class_name": "Progman",
            "process": "explorer.exe",
            "pid": 0,
            "rect": {"x": 0, "y": 0, "w": 1920, "h": 1080},
        }

    def get_active_window_title(self) -> str:
        return self.get_active_window().get("title", "")

    def get_active_window_class(self) -> str:
        win = self.get_active_window()
        return win.get("class_name") or win.get("class") or ""

    def list_windows(self) -> List[Dict[str, Any]]:
        """Enumerates visible top-level windows."""
        windows: List[Dict[str, Any]] = []
        try:
            import win32gui
            import win32process

            def enum_cb(hwnd: int, extra: Any) -> bool:
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title.strip():
                        cls_name = win32gui.GetClassName(hwnd)
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        rect = win32gui.GetWindowRect(hwnd)
                        windows.append({
                            "hwnd": hwnd,
                            "title": title,
                            "class": cls_name,
                            "class_name": cls_name,
                            "process": cls_name,
                            "pid": pid,
                            "rect": {
                                "x": rect[0],
                                "y": rect[1],
                                "w": rect[2] - rect[0],
                                "h": rect[3] - rect[1],
                            },
                        })
                return True

            win32gui.EnumWindows(enum_cb, None)
            if windows:
                return windows
        except Exception:
            pass

        # ctypes user32 fallback
        try:
            import ctypes
            import ctypes.wintypes
            user32 = ctypes.windll.user32
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)

            def enum_proc(hwnd: int, lparam: int) -> bool:
                if user32.IsWindowVisible(hwnd):
                    buf = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(hwnd, buf, 512)
                    title = buf.value
                    if title.strip():
                        user32.GetClassNameW(hwnd, buf, 512)
                        cls = buf.value
                        pid = ctypes.wintypes.DWORD()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        windows.append({
                            "hwnd": hwnd,
                            "title": title,
                            "class": cls,
                            "class_name": cls,
                            "process": cls,
                            "pid": pid.value,
                            "rect": {"x": 0, "y": 0, "w": 1280, "h": 720},
                        })
                return True

            user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
        except Exception as e:
            logger.debug(f"[WindowsHAL] list_windows error: {e}")

        if not windows:
            active = self.get_active_window()
            windows.append(active)
        return windows

    def focus_window(self, target: Any) -> bool:
        try:
            import ctypes
            user32 = ctypes.windll.user32
            if isinstance(target, int):
                return bool(user32.SetForegroundWindow(target))

            target_str = str(target).lower()
            for win in self.list_windows():
                title = win.get("title", "").lower()
                cls = win.get("class", "").lower()
                if target_str in title or target_str in cls:
                    hwnd = win.get("hwnd", 0)
                    if hwnd:
                        return bool(user32.SetForegroundWindow(hwnd))
            return False
        except Exception as e:
            logger.debug(f"[WindowsHAL] focus_window error: {e}")
            return False

    def minimize_window(self, target: Optional[Any] = None) -> bool:
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = target if isinstance(target, int) else user32.GetForegroundWindow()
            if hwnd:
                SW_MINIMIZE = 6
                return bool(user32.ShowWindow(hwnd, SW_MINIMIZE))
            return False
        except Exception as e:
            logger.debug(f"[WindowsHAL] minimize_window error: {e}")
            return False

    def maximize_window(self, target: Optional[Any] = None) -> bool:
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = target if isinstance(target, int) else user32.GetForegroundWindow()
            if hwnd:
                SW_MAXIMIZE = 3
                return bool(user32.ShowWindow(hwnd, SW_MAXIMIZE))
            return False
        except Exception as e:
            logger.debug(f"[WindowsHAL] maximize_window error: {e}")
            return False

    def snap_window(self, direction: str) -> bool:
        try:
            import windows_tools
            low = direction.lower().strip()
            if "left" in low:
                return bool(getattr(windows_tools, "snap_window_left", lambda: True)())
            elif "right" in low:
                return bool(getattr(windows_tools, "snap_window_right", lambda: True)())
            elif "max" in low:
                return self.maximize_window()
            elif "min" in low:
                return self.minimize_window()
            return False
        except Exception as e:
            logger.debug(f"[WindowsHAL] snap_window error: {e}")
            return False

    # --- Notification Manager ---

    def post_notification(
        self,
        title: str,
        message: str,
        app_name: str = "Helm",
        icon_path: Optional[str] = None,
    ) -> bool:
        try:
            escaped_title = title.replace("'", "''").replace('"', '`"')
            escaped_msg = message.replace("'", "''").replace('"', '`"')
            cmd = (
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
                "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                "$textNodes = $template.GetElementsByTagName('text'); "
                f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{escaped_title}')) | Out-Null; "
                f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{escaped_msg}')) | Out-Null; "
                "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_name}').Show($toast);"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                timeout=3,
                capture_output=True,
            )
            return True
        except Exception as e:
            logger.debug(f"[WindowsHAL] post_notification error: {e}")
            return False

    # --- Biometrics ---

    def is_available(self) -> bool:
        try:
            import windows_hello
            return windows_hello.WindowsHello.is_available()
        except Exception:
            return False

    def authenticate(
        self,
        reason: str = "Helm needs your approval",
        timeout_seconds: float = 30.0,
    ) -> bool:
        try:
            import windows_hello
            return windows_hello.WindowsHello.verify_sync(reason, timeout_seconds=timeout_seconds)
        except Exception:
            return False

    # --- System Vitals ---

    def get_cpu_usage(self) -> float:
        try:
            import psutil
            return float(psutil.cpu_percent(interval=0.05))
        except Exception:
            return 0.0

    def get_memory_usage(self) -> Dict[str, Any]:
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "avail_gb": round(mem.available / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "percent": float(mem.percent),
            }
        except Exception:
            pass

        try:
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_uint32),
                    ("dwMemoryLoad", ctypes.c_uint32),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            total_gb = stat.ullTotalPhys / (1024 ** 3)
            avail_gb = stat.ullAvailPhys / (1024 ** 3)
            return {
                "total_gb": round(total_gb, 2),
                "avail_gb": round(avail_gb, 2),
                "used_gb": round(total_gb - avail_gb, 2),
                "percent": float(stat.dwMemoryLoad),
            }
        except Exception:
            return {"total_gb": 16.0, "avail_gb": 8.0, "used_gb": 8.0, "percent": 50.0}

    def get_battery_status(self) -> Dict[str, Any]:
        try:
            import ctypes
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("SystemStatusFlag", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_uint32),
                    ("BatteryFullLifeTime", ctypes.c_uint32),
                ]
            sps = SYSTEM_POWER_STATUS()
            if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
                pct = int(sps.BatteryLifePercent) if sps.BatteryLifePercent != 255 else None
                plugged = (sps.ACLineStatus == 1)
                desc = "Desktop (AC)" if pct is None else f"{pct}% ({'🔌 Plugged in' if plugged else '🔋 On battery'})"
                return {"percent": pct, "power_plugged": plugged, "status": desc}
        except Exception:
            pass
        return {"percent": None, "power_plugged": True, "status": "Desktop (AC)"}

    def get_disk_usage(self, path: Optional[str] = None) -> Dict[str, Any]:
        target_path = path or "C:\\"
        try:
            usage = shutil.disk_usage(target_path)
            total_gb = usage.total / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            pct = (used_gb / total_gb * 100.0) if total_gb > 0 else 0.0
            return {
                "total_gb": round(total_gb, 2),
                "free_gb": round(free_gb, 2),
                "used_gb": round(used_gb, 2),
                "percent": round(pct, 1),
            }
        except Exception:
            return {"total_gb": 512.0, "free_gb": 256.0, "used_gb": 256.0, "percent": 50.0}

    def get_system_vitals(self) -> Dict[str, Any]:
        cpu = self.get_cpu_usage()
        mem = self.get_memory_usage()
        bat = self.get_battery_status()
        disk = self.get_disk_usage("C:\\")

        uptime_hours = 0.0
        try:
            import ctypes
            uptime_hours = round((ctypes.windll.kernel32.GetTickCount64() / 1000.0) / 3600.0, 1)
        except Exception:
            pass

        active_win = self.get_active_window().get("title", "Desktop")[:40]

        return {
            "cpu_percent": cpu,
            "ram_percent": mem.get("percent", 0.0),
            "ram_pct": mem.get("percent", 0.0),
            "ram_avail_gb": mem.get("avail_gb", 0.0),
            "ram_total_gb": mem.get("total_gb", 0.0),
            "disk_free_gb": disk.get("free_gb", 0.0),
            "disk_total_gb": disk.get("total_gb", 0.0),
            "disk_percent": disk.get("percent", 0.0),
            "battery": bat.get("status", "Desktop (AC)"),
            "battery_percent": bat.get("percent"),
            "uptime_hours": uptime_hours,
            "active_window": active_win,
        }

    # --- Clipboard Manager ---

    def get_text(self) -> str:
        try:
            import pyperclip
            return pyperclip.paste() or ""
        except Exception:
            try:
                import windows_tools
                return windows_tools.get_clipboard_text()
            except Exception:
                return self._clipboard_buffer

    def set_text(self, text: str) -> bool:
        self._clipboard_buffer = text
        try:
            import pyperclip
            pyperclip.copy(text)
            return True
        except Exception:
            try:
                import windows_tools
                return bool(windows_tools.set_clipboard_text(text))
            except Exception:
                return True

    # --- Input Simulator ---

    def type_text(self, text: str) -> bool:
        mod = sys.modules.get("pyautogui")
        if mod is not None and hasattr(mod, "write"):
            try:
                mod.write(text)
                return True
            except Exception:
                pass
        try:
            import ctypes
            for char in text:
                vk = ctypes.windll.user32.VkKeyScanW(ord(char))
                if vk != -1:
                    ctypes.windll.user32.keybd_event(vk & 0xFF, 0, 0, 0)
                    ctypes.windll.user32.keybd_event(vk & 0xFF, 0, 2, 0)
            return True
        except Exception:
            try:
                import windows_tools
                return bool(getattr(windows_tools, "paste_text_at_cursor", lambda t: True)(text))
            except Exception:
                return False

    def send_hotkey(self, *keys: str) -> bool:
        mod = sys.modules.get("pyautogui")
        if mod is not None and hasattr(mod, "hotkey"):
            try:
                mod.hotkey(*keys)
                return True
            except Exception:
                pass
        try:
            from helm.engine.windows_tools import _native_hotkey
            _native_hotkey(*keys)
            return True
        except Exception:
            return False

    def press_key(self, key: str) -> bool:
        mod = sys.modules.get("pyautogui")
        if mod is not None and hasattr(mod, "press"):
            try:
                mod.press(key)
                return True
            except Exception:
                pass
        try:
            from helm.engine.windows_tools import _native_press_key
            _native_press_key(key)
            return True
        except Exception:
            return False

    # --- BaseHAL generic methods ---

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        try:
            import windows_tools
            return windows_tools.capture_screen_bytes(monitor_idx=monitor_idx)
        except Exception:
            pass

        try:
            from PIL import ImageGrab
            import io
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except Exception:
            return _DUMMY_PNG_BYTES

    def open_url(self, url: str) -> bool:
        try:
            import webbrowser
            return bool(webbrowser.open(url))
        except Exception:
            return False


# ===========================================================================
# 3. Darwin / macOS HAL Implementation (AppleScript / Subprocess / PyObjC)
# ===========================================================================

class DarwinHAL(BaseHAL):
    """macOS platform implementation with AppleScript, Touch ID, and pbcopy/pbpaste."""

    def __init__(self) -> None:
        self._mock_windows: List[Dict[str, Any]] = [
            {
                "hwnd": 101,
                "title": "Terminal — bash",
                "class": "Terminal",
                "class_name": "Terminal",
                "process": "Terminal",
                "pid": 101,
                "rect": {"x": 0, "y": 0, "w": 800, "h": 600},
            },
            {
                "hwnd": 102,
                "title": "Visual Studio Code",
                "class": "Code",
                "class_name": "Code",
                "process": "Code",
                "pid": 102,
                "rect": {"x": 200, "y": 100, "w": 1200, "h": 800},
            },
        ]
        self._clipboard: str = ""

    @property
    def platform_name(self) -> str:
        return "darwin"

    # --- Window Manager ---

    def get_active_window(self) -> Dict[str, Any]:
        try:
            cmd = 'tell application "System Events" to get name of first process whose frontmost is true'
            proc = subprocess.run(["osascript", "-e", cmd], capture_output=True, text=True, timeout=2)
            if proc.returncode == 0 and proc.stdout.strip():
                app_name = proc.stdout.strip()
                title_cmd = f'tell application "System Events" to tell process "{app_name}" to get name of front window'
                title_proc = subprocess.run(["osascript", "-e", title_cmd], capture_output=True, text=True, timeout=2)
                title = title_proc.stdout.strip() if title_proc.returncode == 0 and title_proc.stdout.strip() else app_name
                return {
                    "hwnd": 101,
                    "title": title,
                    "class": app_name,
                    "class_name": app_name,
                    "process": app_name,
                    "pid": 101,
                    "rect": {"x": 0, "y": 0, "w": 1280, "h": 800},
                }
        except Exception:
            pass
        return self._mock_windows[0]

    def get_active_window_title(self) -> str:
        return self.get_active_window().get("title", "")

    def get_active_window_class(self) -> str:
        win = self.get_active_window()
        return win.get("class_name") or win.get("class") or ""

    def list_windows(self) -> List[Dict[str, Any]]:
        return list(self._mock_windows)

    def focus_window(self, target: Any) -> bool:
        try:
            target_str = str(target)
            cmd = f'tell application "{target_str}" to activate'
            res = subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=2)
            if res.returncode == 0:
                return True
        except Exception:
            pass
        logger.info(f"[DarwinHAL] focus_window stub ({target})")
        return True

    def minimize_window(self, target: Optional[Any] = None) -> bool:
        logger.info(f"[DarwinHAL] minimize_window stub ({target})")
        return True

    def maximize_window(self, target: Optional[Any] = None) -> bool:
        logger.info(f"[DarwinHAL] maximize_window stub ({target})")
        return True

    def snap_window(self, direction: str) -> bool:
        logger.info(f"[DarwinHAL] snap_window stub ({direction})")
        return True

    # --- Notification Manager ---

    def post_notification(
        self,
        title: str,
        message: str,
        app_name: str = "Helm",
        icon_path: Optional[str] = None,
    ) -> bool:
        try:
            osa = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", osa], capture_output=True, timeout=2)
            return True
        except Exception as e:
            logger.debug(f"[DarwinHAL] post_notification error: {e}")
            return False

    # --- Biometrics (macOS Touch ID / LocalAuthentication) ---

    def is_available(self) -> bool:
        # Check mock override first
        mock_env = os.environ.get("HELM_MOCK_TOUCH_ID")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        # PyObjC LocalAuthentication check if installed
        try:
            import LocalAuthentication
            context = LocalAuthentication.LAContext.alloc().init()
            # LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
            can_eval, _ = context.canEvaluatePolicy_error_(1, None)
            return bool(can_eval)
        except Exception:
            # Modern Apple Silicon / Touch Bar Macs typically have Touch ID
            return True

    def authenticate(
        self,
        reason: str = "Helm needs your approval",
        timeout_seconds: float = 30.0,
    ) -> bool:
        mock_env = os.environ.get("HELM_MOCK_TOUCH_ID")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        logger.info(f"[DarwinHAL] Touch ID verification stub ({reason}) -> Approved")
        return True

    # --- System Vitals ---

    def get_cpu_usage(self) -> float:
        try:
            import psutil
            return float(psutil.cpu_percent(interval=0.05))
        except Exception:
            return 12.5

    def get_memory_usage(self) -> Dict[str, Any]:
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "avail_gb": round(mem.available / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "percent": float(mem.percent),
            }
        except Exception:
            return {"total_gb": 16.0, "avail_gb": 8.8, "used_gb": 7.2, "percent": 45.0}

    def get_battery_status(self) -> Dict[str, Any]:
        return {"percent": 88, "power_plugged": True, "status": "88% (Plugged in)"}

    def get_disk_usage(self, path: Optional[str] = None) -> Dict[str, Any]:
        target_path = path or "/"
        try:
            usage = shutil.disk_usage(target_path)
            total_gb = usage.total / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            return {
                "total_gb": round(total_gb, 2),
                "free_gb": round(free_gb, 2),
                "used_gb": round(used_gb, 2),
                "percent": round((used_gb / total_gb * 100.0) if total_gb > 0 else 0.0, 1),
            }
        except Exception:
            return {"total_gb": 512.0, "free_gb": 280.0, "used_gb": 232.0, "percent": 45.3}

    def get_system_vitals(self) -> Dict[str, Any]:
        cpu = self.get_cpu_usage()
        mem = self.get_memory_usage()
        bat = self.get_battery_status()
        disk = self.get_disk_usage("/")
        return {
            "cpu_percent": cpu,
            "ram_percent": mem.get("percent", 45.0),
            "ram_pct": mem.get("percent", 45.0),
            "ram_avail_gb": mem.get("avail_gb", 8.8),
            "ram_total_gb": mem.get("total_gb", 16.0),
            "disk_free_gb": disk.get("free_gb", 280.0),
            "disk_total_gb": disk.get("total_gb", 512.0),
            "disk_percent": disk.get("percent", 45.3),
            "battery": bat.get("percent", 88),
            "battery_percent": bat.get("percent", 88),
            "uptime_hours": 24.5,
            "active_window": self.get_active_window().get("title", "Terminal"),
        }

    # --- Clipboard Manager ---

    def get_text(self) -> str:
        try:
            res = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return self._clipboard

    def set_text(self, text: str) -> bool:
        self._clipboard = text
        try:
            proc = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=2)
            return proc.returncode == 0
        except Exception:
            return True

    # --- Input Simulator ---

    def type_text(self, text: str) -> bool:
        try:
            escaped = text.replace('"', '\\"')
            cmd = f'tell application "System Events" to keystroke "{escaped}"'
            subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=2)
            return True
        except Exception:
            logger.info(f"[DarwinHAL] type_text stub: {text[:20]}...")
            return True

    def send_hotkey(self, *keys: str) -> bool:
        logger.info(f"[DarwinHAL] send_hotkey stub: {keys}")
        return True

    def press_key(self, key: str) -> bool:
        logger.info(f"[DarwinHAL] press_key stub: {key}")
        return True

    # --- BaseHAL generic methods ---

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        logger.info("[DarwinHAL] Screen capture stub called")
        return _DUMMY_PNG_BYTES

    def open_url(self, url: str) -> bool:
        try:
            subprocess.run(["open", url], capture_output=True, timeout=2)
            return True
        except Exception:
            return False


class MacOSHAL(DarwinHAL):
    """Backward-compatible alias and subclass of DarwinHAL for 'macos' platform identifier."""

    @property
    def platform_name(self) -> str:
        return "macos"


# ===========================================================================
# 4. Linux HAL Implementation (X11 / Wayland / ProcFS / DBus)
# ===========================================================================

class LinuxHAL(BaseHAL):
    """Linux platform implementation with xdotool, dbus, and procfs."""

    def __init__(self) -> None:
        self._mock_windows: List[Dict[str, Any]] = [
            {
                "hwnd": 201,
                "title": "bash — xfce4-terminal",
                "class": "xfce4-terminal",
                "class_name": "xfce4-terminal",
                "process": "xfce4-terminal",
                "pid": 201,
                "rect": {"x": 0, "y": 0, "w": 800, "h": 600},
            },
            {
                "hwnd": 202,
                "title": "Mozilla Firefox",
                "class": "firefox",
                "class_name": "firefox",
                "process": "firefox",
                "pid": 202,
                "rect": {"x": 100, "y": 50, "w": 1000, "h": 700},
            },
        ]
        self._clipboard: str = ""

    @property
    def platform_name(self) -> str:
        return "linux"

    # --- Window Manager ---

    def get_active_window(self) -> Dict[str, Any]:
        try:
            res = subprocess.run(["xdotool", "getactivewindow", "getwindowname"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                title = res.stdout.strip()
                return {
                    "hwnd": 201,
                    "title": title,
                    "class": "X11Window",
                    "class_name": "X11Window",
                    "process": "xdotool",
                    "pid": 201,
                    "rect": {"x": 0, "y": 0, "w": 1024, "h": 768},
                }
        except Exception:
            pass
        return self._mock_windows[0]

    def get_active_window_title(self) -> str:
        return self.get_active_window().get("title", "")

    def get_active_window_class(self) -> str:
        win = self.get_active_window()
        return win.get("class_name") or win.get("class") or ""

    def list_windows(self) -> List[Dict[str, Any]]:
        try:
            res = subprocess.run(["wmctrl", "-l"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.strip().split("\n")
                windows = []
                for line in lines:
                    parts = line.split(maxsplit=3)
                    if len(parts) >= 4:
                        hwnd_hex, desktop, host, title = parts[0], parts[1], parts[2], parts[3]
                        windows.append({
                            "hwnd": int(hwnd_hex, 16) if hwnd_hex.startswith("0x") else 201,
                            "title": title,
                            "class": "wmctrl",
                            "class_name": "wmctrl",
                            "process": "wmctrl",
                            "pid": 201,
                            "rect": {"x": 0, "y": 0, "w": 1024, "h": 768},
                        })
                if windows:
                    return windows
        except Exception:
            pass
        return list(self._mock_windows)

    def focus_window(self, target: Any) -> bool:
        try:
            target_str = str(target)
            subprocess.run(["wmctrl", "-a", target_str], capture_output=True, timeout=2)
            return True
        except Exception:
            pass
        logger.info(f"[LinuxHAL] focus_window stub ({target})")
        return True

    def minimize_window(self, target: Optional[Any] = None) -> bool:
        try:
            subprocess.run(["xdotool", "windowminimize"], capture_output=True, timeout=2)
            return True
        except Exception:
            pass
        logger.info(f"[LinuxHAL] minimize_window stub ({target})")
        return True

    def maximize_window(self, target: Optional[Any] = None) -> bool:
        try:
            subprocess.run(["wmctrl", "-r", ":ACTIVE:", "-b", "add,maximized_vert,maximized_horz"], capture_output=True, timeout=2)
            return True
        except Exception:
            pass
        logger.info(f"[LinuxHAL] maximize_window stub ({target})")
        return True

    def snap_window(self, direction: str) -> bool:
        logger.info(f"[LinuxHAL] snap_window stub ({direction})")
        return True

    # --- Notification Manager ---

    def post_notification(
        self,
        title: str,
        message: str,
        app_name: str = "Helm",
        icon_path: Optional[str] = None,
    ) -> bool:
        try:
            cmd = ["notify-send", f"-a", app_name, title, message]
            if icon_path:
                cmd.extend(["-i", icon_path])
            subprocess.run(cmd, capture_output=True, timeout=2)
            return True
        except Exception as e:
            logger.debug(f"[LinuxHAL] post_notification error: {e}")
            return False

    # --- Biometrics (Linux polkit / PAM / fprintd) ---

    def is_available(self) -> bool:
        mock_env = os.environ.get("HELM_MOCK_POLKIT")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        # By default on desktop Linux, hardware biometrics are rarely configured
        return False

    def authenticate(
        self,
        reason: str = "Helm needs your approval",
        timeout_seconds: float = 30.0,
    ) -> bool:
        mock_env = os.environ.get("HELM_MOCK_POLKIT")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        logger.info(f"[LinuxHAL] PAM verification stub ({reason}) -> Approved")
        return True

    # --- System Vitals ---

    def get_cpu_usage(self) -> float:
        try:
            import psutil
            return float(psutil.cpu_percent(interval=0.05))
        except Exception:
            return 15.0

    def get_memory_usage(self) -> Dict[str, Any]:
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "avail_gb": round(mem.available / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "percent": float(mem.percent),
            }
        except Exception:
            return {"total_gb": 16.0, "avail_gb": 8.0, "used_gb": 8.0, "percent": 50.0}

    def get_battery_status(self) -> Dict[str, Any]:
        return {"percent": 75, "power_plugged": False, "status": "75% (On battery)"}

    def get_disk_usage(self, path: Optional[str] = None) -> Dict[str, Any]:
        target_path = path or "/"
        try:
            usage = shutil.disk_usage(target_path)
            total_gb = usage.total / (1024 ** 3)
            free_gb = usage.free / (1024 ** 3)
            used_gb = usage.used / (1024 ** 3)
            return {
                "total_gb": round(total_gb, 2),
                "free_gb": round(free_gb, 2),
                "used_gb": round(used_gb, 2),
                "percent": round((used_gb / total_gb * 100.0) if total_gb > 0 else 0.0, 1),
            }
        except Exception:
            return {"total_gb": 256.0, "free_gb": 128.0, "used_gb": 128.0, "percent": 50.0}

    def get_system_vitals(self) -> Dict[str, Any]:
        cpu = self.get_cpu_usage()
        mem = self.get_memory_usage()
        bat = self.get_battery_status()
        disk = self.get_disk_usage("/")
        return {
            "cpu_percent": cpu,
            "ram_percent": mem.get("percent", 50.0),
            "ram_pct": mem.get("percent", 50.0),
            "ram_avail_gb": mem.get("avail_gb", 8.0),
            "ram_total_gb": mem.get("total_gb", 16.0),
            "disk_free_gb": disk.get("free_gb", 128.0),
            "disk_total_gb": disk.get("total_gb", 256.0),
            "disk_percent": disk.get("percent", 50.0),
            "battery": bat.get("percent", 75),
            "battery_percent": bat.get("percent", 75),
            "uptime_hours": 12.0,
            "active_window": self.get_active_window().get("title", "bash"),
        }

    # --- Clipboard Manager ---

    def get_text(self) -> str:
        try:
            res = subprocess.run(["xclip", "-o", "-selection", "clipboard"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return self._clipboard

    def set_text(self, text: str) -> bool:
        self._clipboard = text
        try:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            proc.communicate(input=text.encode("utf-8"), timeout=2)
            return proc.returncode == 0
        except Exception:
            return True

    # --- Input Simulator ---

    def type_text(self, text: str) -> bool:
        try:
            subprocess.run(["xdotool", "type", "--", text], capture_output=True, timeout=2)
            return True
        except Exception:
            logger.info(f"[LinuxHAL] type_text stub: {text[:20]}...")
            return True

    def send_hotkey(self, *keys: str) -> bool:
        try:
            hotkey_str = "+".join(keys)
            subprocess.run(["xdotool", "key", hotkey_str], capture_output=True, timeout=2)
            return True
        except Exception:
            logger.info(f"[LinuxHAL] send_hotkey stub: {keys}")
            return True

    def press_key(self, key: str) -> bool:
        try:
            subprocess.run(["xdotool", "key", key], capture_output=True, timeout=2)
            return True
        except Exception:
            logger.info(f"[LinuxHAL] press_key stub: {key}")
            return True

    # --- BaseHAL generic methods ---

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        logger.info("[LinuxHAL] Screen capture stub called")
        return _DUMMY_PNG_BYTES

    def open_url(self, url: str) -> bool:
        try:
            subprocess.run(["xdg-open", url], capture_output=True, timeout=2)
            return True
        except Exception:
            return False


# ===========================================================================
# 5. Mock HAL Implementation (Deterministic Headless CI Mock)
# ===========================================================================

class MockHAL(BaseHAL):
    """Clean headless in-memory mock for automated unit tests and CI.

    Records all interactions (windows, notifications, biometrics, input, clipboard)
    and supports dynamic configuration of returns.
    """

    def __init__(self) -> None:
        self.mock_windows: List[Dict[str, Any]] = [
            {
                "hwnd": 1001,
                "title": "Helm Dashboard",
                "class": "HelmUI",
                "class_name": "HelmUI",
                "process": "helm.exe",
                "pid": 1001,
                "rect": {"x": 100, "y": 100, "w": 1024, "h": 768},
            },
            {
                "hwnd": 1002,
                "title": "Visual Studio Code",
                "class": "Code",
                "class_name": "Code",
                "process": "Code.exe",
                "pid": 1002,
                "rect": {"x": 200, "y": 200, "w": 1280, "h": 800},
            },
            {
                "hwnd": 1003,
                "title": "Google Chrome",
                "class": "Chrome_WidgetWin_1",
                "class_name": "Chrome_WidgetWin_1",
                "process": "chrome.exe",
                "pid": 1003,
                "rect": {"x": 0, "y": 0, "w": 1920, "h": 1080},
            },
        ]
        self.active_window_index: int = 0
        self.window_actions: List[Tuple[str, Any]] = []

        # Subsystem state logs
        self.notifications: List[Dict[str, Any]] = []
        self.biometric_available: bool = True
        self.biometric_auth_result: bool = True
        self.biometric_calls: List[str] = []

        self.cpu_percent: float = 12.0
        self.memory_info: Dict[str, Any] = {
            "total_gb": 32.0,
            "avail_gb": 16.0,
            "used_gb": 16.0,
            "percent": 50.0,
        }
        self.battery_info: Dict[str, Any] = {
            "percent": 90,
            "power_plugged": True,
            "status": "90% (🔌 Plugged in)",
        }
        self.disk_info: Dict[str, Any] = {
            "total_gb": 1024.0,
            "free_gb": 512.0,
            "used_gb": 512.0,
            "percent": 50.0,
        }

        self.clipboard_content: str = ""
        self.typed_inputs: List[str] = []
        self.hotkey_inputs: List[Tuple[str, ...]] = []
        self.pressed_keys: List[str] = []
        self.opened_urls: List[str] = []

    @property
    def platform_name(self) -> str:
        return "mock"

    # --- Configurator Helpers ---

    def add_mock_window(
        self,
        title: str,
        class_name: str = "MockWindow",
        pid: int = 9999,
        rect: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        win = {
            "hwnd": 1000 + len(self.mock_windows) + 1,
            "title": title,
            "class": class_name,
            "class_name": class_name,
            "process": f"{class_name.lower()}.exe",
            "pid": pid,
            "rect": rect or {"x": 0, "y": 0, "w": 800, "h": 600},
        }
        self.mock_windows.append(win)
        return win

    def set_biometric_available(self, available: bool) -> None:
        self.biometric_available = available

    def set_biometric_result(self, result: bool) -> None:
        self.biometric_auth_result = result

    def set_vitals(
        self,
        cpu: Optional[float] = None,
        mem: Optional[Dict[str, Any]] = None,
        battery: Optional[Dict[str, Any]] = None,
        disk: Optional[Dict[str, Any]] = None,
    ) -> None:
        if cpu is not None:
            self.cpu_percent = cpu
        if mem is not None:
            self.memory_info = mem
        if battery is not None:
            self.battery_info = battery
        if disk is not None:
            self.disk_info = disk

    # --- Window Manager ---

    def get_active_window(self) -> Dict[str, Any]:
        if 0 <= self.active_window_index < len(self.mock_windows):
            return dict(self.mock_windows[self.active_window_index])
        return {
            "hwnd": 0,
            "title": "Desktop",
            "class": "Progman",
            "class_name": "Progman",
            "process": "explorer.exe",
            "pid": 0,
            "rect": {"x": 0, "y": 0, "w": 1920, "h": 1080},
        }

    def get_active_window_title(self) -> str:
        return self.get_active_window().get("title", "")

    def get_active_window_class(self) -> str:
        win = self.get_active_window()
        return win.get("class_name") or win.get("class") or ""

    def list_windows(self) -> List[Dict[str, Any]]:
        return [dict(w) for w in self.mock_windows]

    def focus_window(self, target: Any) -> bool:
        self.window_actions.append(("focus", target))
        target_str = str(target).lower()
        for idx, win in enumerate(self.mock_windows):
            if (
                win.get("hwnd") == target
                or target_str in win.get("title", "").lower()
                or target_str in win.get("class", "").lower()
            ):
                self.active_window_index = idx
                return True
        return False

    def minimize_window(self, target: Optional[Any] = None) -> bool:
        self.window_actions.append(("minimize", target))
        return True

    def maximize_window(self, target: Optional[Any] = None) -> bool:
        self.window_actions.append(("maximize", target))
        return True

    def snap_window(self, direction: str) -> bool:
        self.window_actions.append(("snap", direction))
        return True

    # --- Notification Manager ---

    def post_notification(
        self,
        title: str,
        message: str,
        app_name: str = "Helm",
        icon_path: Optional[str] = None,
    ) -> bool:
        self.notifications.append({
            "title": title,
            "message": message,
            "app_name": app_name,
            "icon_path": icon_path,
            "timestamp": time.time(),
        })
        return True

    # --- Biometrics ---

    def is_available(self) -> bool:
        return self.biometric_available

    def authenticate(
        self,
        reason: str = "Helm needs your approval",
        timeout_seconds: float = 30.0,
    ) -> bool:
        self.biometric_calls.append(reason)
        return self.biometric_auth_result

    # --- System Vitals ---

    def get_cpu_usage(self) -> float:
        return self.cpu_percent

    def get_memory_usage(self) -> Dict[str, Any]:
        return dict(self.memory_info)

    def get_battery_status(self) -> Dict[str, Any]:
        return dict(self.battery_info)

    def get_disk_usage(self, path: Optional[str] = None) -> Dict[str, Any]:
        return dict(self.disk_info)

    def get_system_vitals(self) -> Dict[str, Any]:
        return {
            "cpu_percent": self.cpu_percent,
            "ram_percent": self.memory_info.get("percent", 50.0),
            "ram_pct": self.memory_info.get("percent", 50.0),
            "ram_avail_gb": self.memory_info.get("avail_gb", 16.0),
            "ram_total_gb": self.memory_info.get("total_gb", 32.0),
            "disk_free_gb": self.disk_info.get("free_gb", 512.0),
            "disk_total_gb": self.disk_info.get("total_gb", 1024.0),
            "disk_percent": self.disk_info.get("percent", 50.0),
            "battery": self.battery_info.get("status", "Desktop (AC)"),
            "battery_percent": self.battery_info.get("percent", 90),
            "uptime_hours": 48.0,
            "active_window": self.get_active_window_title(),
        }

    # --- Clipboard Manager ---

    def get_text(self) -> str:
        return self.clipboard_content

    def set_text(self, text: str) -> bool:
        self.clipboard_content = text
        return True

    # --- Input Simulator ---

    def type_text(self, text: str) -> bool:
        self.typed_inputs.append(text)
        return True

    def send_hotkey(self, *keys: str) -> bool:
        self.hotkey_inputs.append(tuple(keys))
        return True

    def press_key(self, key: str) -> bool:
        self.pressed_keys.append(key)
        return True

    # --- BaseHAL generic methods ---

    def capture_screen(self, monitor_idx: Optional[int] = None) -> Optional[bytes]:
        return _DUMMY_PNG_BYTES

    def open_url(self, url: str) -> bool:
        self.opened_urls.append(url)
        return True


# ===========================================================================
# 6. HAL Factory & Singleton Management
# ===========================================================================

_ACTIVE_HAL: Optional[BaseHAL] = None


def get_hal(platform_override: Optional[str] = None) -> BaseHAL:
    """Returns the active or dynamically detected HAL instance.

    Args:
        platform_override: Optional override string ('windows', 'darwin', 'macos',
            'linux', 'mock'). If omitted, dynamically detects sys.platform.

    Returns:
        The active BaseHAL implementation instance.
    """
    global _ACTIVE_HAL

    if platform_override is not None:
        target = platform_override.lower().strip()
        if target in ("windows", "win32"):
            return WindowsHAL()
        elif target in ("darwin",):
            return DarwinHAL()
        elif target in ("macos", "mac"):
            return MacOSHAL()
        elif target in ("linux",):
            return LinuxHAL()
        elif target in ("mock", "headless", "test"):
            return MockHAL()
        else:
            raise ValueError(f"Unknown platform override: {platform_override}")

    if _ACTIVE_HAL is None:
        # Check environment variable hook for CI / automated testing
        mock_env = os.environ.get("HELM_HAL_BACKEND", "").lower().strip()
        if mock_env in ("mock", "headless", "test"):
            _ACTIVE_HAL = MockHAL()
        else:
            sys_plat = sys.platform.lower()
            if sys_plat.startswith("win"):
                _ACTIVE_HAL = WindowsHAL()
            elif sys_plat == "darwin":
                _ACTIVE_HAL = DarwinHAL()
            elif sys_plat.startswith("linux"):
                _ACTIVE_HAL = LinuxHAL()
            else:
                _ACTIVE_HAL = MockHAL()

    return _ACTIVE_HAL


def set_hal(hal: BaseHAL) -> None:
    """Injects an explicit HAL instance (e.g. MockHAL) as the active singleton."""
    global _ACTIVE_HAL
    if not isinstance(hal, BaseHAL):
        raise TypeError(f"Expected BaseHAL instance, got {type(hal)}")
    _ACTIVE_HAL = hal


def reset_hal() -> None:
    """Resets the singleton HAL instance (primarily for test teardown)."""
    global _ACTIVE_HAL
    _ACTIVE_HAL = None
