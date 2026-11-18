"""homie_ghost_desktop.py - Ghost Mode & Secondary Desktop Automation for Windows.

Enables non-disruptive, background agent automation:
- Creates an isolated Win32 Desktop ('HomieGhostDesktop') via user32.dll CreateDesktopW.
- Launches background automation processes (browsers, scrapers, data entry tools)
  pinned exclusively to the ghost desktop via STARTUPINFO.lpDesktop.
- Physical Mouse Invariant: The agent operates completely in the background without stealing
  the user's physical mouse cursor, window focus, or interrupting active keyboard typing.
"""

from __future__ import annotations

import os
import sys
import time
import ctypes
import subprocess
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("homie.ghost_desktop")

# Win32 Constants
GENERIC_ALL = 0x10000000
DESKTOP_ALL_ACCESS = 0x01FF

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

GHOST_DESKTOP_NAME = "HomieGhostDesktop"


class GhostDesktopManager:
    """Manages an isolated Win32 background desktop for non-disruptive automation."""

    def __init__(self, desktop_name: str = GHOST_DESKTOP_NAME):
        self.desktop_name = desktop_name
        self.hdesk: Optional[int] = None
        self._processes: list[subprocess.Popen] = []

    def get_or_create_desktop(self) -> int:
        """Returns existing or newly created HDESK handle for the ghost desktop."""
        if self.hdesk:
            return self.hdesk

        # Try opening existing desktop first
        hdesk = user32.OpenDesktopW(self.desktop_name, 0, False, DESKTOP_ALL_ACCESS)
        if not hdesk:
            # Create new isolated desktop
            hdesk = user32.CreateDesktopW(
                self.desktop_name,
                None,
                None,
                0,
                DESKTOP_ALL_ACCESS,
                None
            )

        if not hdesk:
            err = ctypes.GetLastError()
            raise RuntimeError(f"Failed to create or open Win32 desktop '{self.desktop_name}' (Error: {err})")

        self.hdesk = hdesk
        logger.info("Ghost desktop '%s' initialized (HDESK: %s)", self.desktop_name, hdesk)
        return self.hdesk

    def launch_in_ghost_desktop(
        self,
        command_args: list[str],
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None
    ) -> subprocess.Popen:
        """Launches a process attached exclusively to the ghost desktop."""
        self.get_or_create_desktop()

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.lpDesktop = self.desktop_name

        proc = subprocess.Popen(
            command_args,
            startupinfo=startupinfo,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        self._processes.append(proc)
        logger.info("Launched process PID %s in ghost desktop '%s'", proc.pid, self.desktop_name)
        return proc

    def list_ghost_windows(self) -> list[dict[str, Any]]:
        """Enumerates visible top-level windows residing on the ghost desktop."""
        self.get_or_create_desktop()
        windows = []

        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def enum_cb(hwnd, lparam):
            if user32.IsWindowVisible(hwnd):
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value
                    pid = ctypes.c_ulong()
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    windows.append({"hwnd": hwnd, "title": title, "pid": pid.value})
            return True

        # Save thread desktop, switch to ghost desktop, enumerate, then restore
        original_desk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        try:
            user32.SetThreadDesktop(self.hdesk)
            user32.EnumDesktopWindows(self.hdesk, EnumWindowsProc(enum_cb), 0)
        finally:
            user32.SetThreadDesktop(original_desk)

        return windows

    def close(self):
        """Terminates spawned ghost processes and closes the desktop handle."""
        for p in self._processes:
            try:
                p.terminate()
            except Exception:
                pass
        self._processes.clear()

        if self.hdesk:
            try:
                user32.CloseDesktop(self.hdesk)
            except Exception:
                pass
            self.hdesk = None
        logger.info("Ghost desktop '%s' closed", self.desktop_name)


_GLOBAL_GHOST_MANAGER: Optional[GhostDesktopManager] = None


def get_ghost_desktop_manager() -> GhostDesktopManager:
    global _GLOBAL_GHOST_MANAGER
    if _GLOBAL_GHOST_MANAGER is None:
        _GLOBAL_GHOST_MANAGER = GhostDesktopManager()
    return _GLOBAL_GHOST_MANAGER


def is_ghost_mode_available() -> bool:
    """Verifies whether Win32 desktop APIs are operational."""
    try:
        mgr = get_ghost_desktop_manager()
        h = mgr.get_or_create_desktop()
        return bool(h)
    except Exception:
        return False


def run_command_in_ghost_desktop(
    command_args: list[str],
    timeout: float = 30.0,
    cwd: Optional[str] = None
) -> dict[str, Any]:
    """Runs a process attached exclusively to the ghost desktop and waits for completion."""
    mgr = get_ghost_desktop_manager()
    try:
        proc = mgr.launch_in_ghost_desktop(command_args, cwd=cwd)
        stdout, stderr = proc.communicate(timeout=timeout)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "desktop": mgr.desktop_name
        }
    except subprocess.TimeoutExpired:
        proc.kill()
        return {
            "ok": False,
            "error": f"Ghost process timed out after {timeout}s",
            "desktop": mgr.desktop_name
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "desktop": mgr.desktop_name
        }

