"""Inject Unicode text into the active Windows caret without using the clipboard."""

import ctypes
import logging
import sys
from ctypes import wintypes
from typing import Optional

logger = logging.getLogger(__name__)

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

ULONG_PTR = ctypes.c_size_t


class KeyBdInput(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HardwareInput(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class MouseInput(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class InputUnion(ctypes.Union):
    _fields_ = [
        ("ki", KeyBdInput),
        ("mi", MouseInput),
        ("hi", HardwareInput),
    ]


class Input(ctypes.Structure):
    _anonymous_ = ("ii",)
    _fields_ = [
        ("type", wintypes.DWORD),
        ("ii", InputUnion),
    ]


_user32 = None
if sys.platform == "win32":
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _user32.GetForegroundWindow.argtypes = []
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(Input), ctypes.c_int]
    _user32.SendInput.restype = wintypes.UINT


def get_foreground_window_handle() -> Optional[int]:
    """Return the foreground HWND, or ``None`` outside Windows / without a window."""
    if _user32 is None:
        return None
    hwnd = _user32.GetForegroundWindow()
    return int(hwnd) if hwnd else None


def _keyboard_events(text: str):
    """Build down/up events for every UTF-16 code unit in ``text``."""
    encoded = text.encode("utf-16-le")
    units = [encoded[index] | (encoded[index + 1] << 8) for index in range(0, len(encoded), 2)]
    events = (Input * (2 * len(units)))()
    for index, unit in enumerate(units):
        events[index * 2] = Input(
            type=INPUT_KEYBOARD,
            ki=KeyBdInput(wVk=0, wScan=unit, dwFlags=KEYEVENTF_UNICODE, time=0, dwExtraInfo=0),
        )
        events[index * 2 + 1] = Input(
            type=INPUT_KEYBOARD,
            ki=KeyBdInput(
                wVk=0,
                wScan=unit,
                dwFlags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                time=0,
                dwExtraInfo=0,
            ),
        )
    return events


def inject_text_at_caret(text: str, expected_hwnd: Optional[int] = None) -> bool:
    """Send text to the active caret using ``SendInput(KEYEVENTF_UNICODE)``.

    When ``expected_hwnd`` is supplied, injection is cancelled if focus has moved
    to another window since recording began. The system clipboard is never read
    or modified.
    """
    if not text or _user32 is None:
        return False

    hwnd = get_foreground_window_handle()
    if hwnd is None:
        logger.warning("Cannot inject dictation because there is no foreground window")
        return False
    if expected_hwnd is not None and hwnd != int(expected_hwnd):
        logger.warning("Dictation cancelled because the foreground window changed")
        return False

    events = _keyboard_events(text)
    sent = _user32.SendInput(len(events), events, ctypes.sizeof(Input))
    if sent != len(events):
        error_code = ctypes.get_last_error()
        logger.warning("SendInput inserted %s of %s events (Windows error %s)", sent, len(events), error_code)
        return False
    return True
