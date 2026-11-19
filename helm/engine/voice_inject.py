"""
Helm Voice Caret Text Injection — System-wide inline text injection.
Pastes transcribed text directly at the current caret/cursor position
in any active foreground application (Word, Slack, VSCode, Browser, etc.).
"""
import sys
import time
import logging
import ctypes
from ctypes import wintypes
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import win32gui
    import win32clipboard
    import win32con
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False
    win32gui = None
    win32clipboard = None
    win32con = None

# ---------------------------------------------------------------------------
# Windows SendInput CTypes structures for Ctrl+V keystroke injection
# ---------------------------------------------------------------------------
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
VK_CONTROL = 0x11
VK_V = 0x56

PUL = ctypes.POINTER(ctypes.c_ulong)


class KeyBdInput(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", PUL),
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
        ("dwExtraInfo", PUL),
    ]


class Input_I(ctypes.Union):
    _fields_ = [
        ("ki", KeyBdInput),
        ("mi", MouseInput),
        ("hi", HardwareInput),
    ]


class Input(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("ii", Input_I),
    ]


def _set_clipboard_win32(text: str, max_retries: int = 5) -> bool:
    """Set clipboard text using win32clipboard with retry mechanism."""
    if not _WIN32_AVAILABLE or win32clipboard is None:
        raise RuntimeError("win32clipboard is not available")

    last_err = None
    for attempt in range(max_retries):
        try:
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text, win32con.CF_UNICODETEXT)
                return True
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            last_err = e
            time.sleep(0.02)
    raise RuntimeError(f"Could not open/set clipboard: {last_err}")


def _send_ctrl_v_sendinput() -> bool:
    """Simulate Ctrl+V via user32.SendInput to paste clipboard text at caret."""
    user32 = ctypes.windll.user32
    extra = ctypes.c_ulong(0)
    p_extra = ctypes.pointer(extra)

    # Input events: Ctrl DOWN -> V DOWN -> V UP -> Ctrl UP
    inputs = (Input * 4)(
        Input(type=INPUT_KEYBOARD, ii=Input_I(ki=KeyBdInput(wVk=VK_CONTROL, wScan=0, dwFlags=0, time=0, dwExtraInfo=p_extra))),
        Input(type=INPUT_KEYBOARD, ii=Input_I(ki=KeyBdInput(wVk=VK_V, wScan=0, dwFlags=0, time=0, dwExtraInfo=p_extra))),
        Input(type=INPUT_KEYBOARD, ii=Input_I(ki=KeyBdInput(wVk=VK_V, wScan=0, dwFlags=KEYEVENTF_KEYUP, time=0, dwExtraInfo=p_extra))),
        Input(type=INPUT_KEYBOARD, ii=Input_I(ki=KeyBdInput(wVk=VK_CONTROL, wScan=0, dwFlags=KEYEVENTF_KEYUP, time=0, dwExtraInfo=p_extra))),
    )

    sent = user32.SendInput(len(inputs), inputs, ctypes.sizeof(Input))
    if sent != len(inputs):
        raise RuntimeError(f"SendInput sent only {sent}/{len(inputs)} events")
    return True


def _fallback_paste(text: str) -> bool:
    """
    Fallback paste mechanism using pyperclip and keyboard.send('ctrl+v') or native Win32 keybd_event.
    """
    import pyperclip
    pyperclip.copy(text)

    try:
        import keyboard
        keyboard.send("ctrl+v")
        return True
    except Exception:
        logger.debug("[VoiceInject] keyboard module not available, using native keybd_event fallback")
        try:
            import ctypes
            VK_CONTROL = 0x11
            VK_V = 0x56
            KEYEVENTF_KEYUP = 0x0002
            ctypes.windll.user32.keybd_event(VK_CONTROL, 0, 0, 0)
            ctypes.windll.user32.keybd_event(VK_V, 0, 0, 0)
            ctypes.windll.user32.keybd_event(VK_V, 0, KEYEVENTF_KEYUP, 0)
            ctypes.windll.user32.keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0)
            return True
        except Exception as p_err:
            raise RuntimeError(f"Fallback keyboard injection failed: {p_err}")


def inject_text_at_caret(text: str) -> bool:
    """
    Inject text at current cursor position in the foreground application window.

    Steps:
    1. Obtains the active foreground window handle via win32gui.GetForegroundWindow()
    2. Uses win32clipboard + SendInput with Ctrl+V to paste the text at the caret
    3. Falls back to pyperclip + keyboard.send('ctrl+v') if direct paste fails.

    Args:
        text: Transcribed speech text to paste at the caret.

    Returns:
        bool: True if injection succeeded, False otherwise.
    """
    if not text:
        return False

    hwnd = 0
    if _WIN32_AVAILABLE and win32gui is not None:
        try:
            hwnd = win32gui.GetForegroundWindow()
            logger.debug(f"[VoiceInject] Active foreground window handle: {hwnd}")
        except Exception as e:
            logger.warning(f"[VoiceInject] GetForegroundWindow query failed: {e}")

    # Primary injection path: win32clipboard + SendInput
    try:
        if not _WIN32_AVAILABLE:
            raise RuntimeError("win32 modules unavailable")
        _set_clipboard_win32(text)
        time.sleep(0.01)  # Brief yield for clipboard settle
        _send_ctrl_v_sendinput()
        logger.info(f"[VoiceInject] Injected text via win32clipboard + SendInput (hwnd={hwnd})")
        return True
    except Exception as direct_err:
        logger.warning(
            f"[VoiceInject] win32 direct paste failed ({direct_err}), falling back to pyperclip + keyboard"
        )
        try:
            _fallback_paste(text)
            logger.info("[VoiceInject] Injected text via fallback mechanism")
            return True
        except Exception as fallback_err:
            logger.error(f"[VoiceInject] All text injection methods failed: {fallback_err}")
            return False
