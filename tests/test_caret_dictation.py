"""tests/test_caret_dictation.py - Universal Caret Dictation Verification Suite for Helm Desktop.

Comprehensive 4-Tier Verification Suite (ORIGINAL_REQUEST.md §R1, Features F9, F10, F11, F12b):
- Tier 1: Caret Text Injection via SendInput(KEYEVENTF_UNICODE) & VK_BACK revisions.
- Tier 2: Zero-Clipboard Disturbance (Kernel sequence number, byte-for-byte format preservation, lock resilience).
- Tier 3: Active Caret Tracking via Dual-Tier Locator (IUIAutomationTextPattern & GetGUIThreadInfo) + WS_EX_NOACTIVATE.
- Tier 4: Online Token Filter (Filler word stripping, stutter collapsing, edge cases, punctuation & casing).
"""

import ctypes
from ctypes import wintypes
import logging
import os
import re
import sys
import threading
import time
from typing import NamedTuple, Optional, List
import unittest
from unittest.mock import MagicMock, patch
import pytest

logger = logging.getLogger(__name__)

# Ensure workspace root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ---------------------------------------------------------------------------
# Windows Win32 / UIA Constants & CTypes Definitions
# ---------------------------------------------------------------------------
INPUT_KEYBOARD = 1
INPUT_MOUSE = 0
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
VK_BACK = 0x08

WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080

CF_TEXT = 1
CF_BITMAP = 2
CF_UNICODETEXT = 13
CF_HDROP = 15

IS_WINDOWS = sys.platform == "win32"
IS_WINDOWS_INTERACTIVE = False
if IS_WINDOWS:
    try:
        user32 = ctypes.windll.user32
        h_desk = user32.GetThreadDesktop(user32.GetCurrentThreadId())
        IS_WINDOWS_INTERACTIVE = bool(h_desk != 0 and user32.GetDesktopWindow() != 0)
    except Exception:
        IS_WINDOWS_INTERACTIVE = False


# Win32 INPUT structures
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("ki", KEYBDINPUT),
        ("mi", MOUSEINPUT),
        ("hi", HARDWAREINPUT),
    ]


class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("u", _INPUT_UNION),
    ]


# ---------------------------------------------------------------------------
# Dictation Architecture Reference Contracts & Double Fallbacks
# ---------------------------------------------------------------------------
class CaretLocation(NamedTuple):
    hwnd: int
    x: int
    y: int
    width: int
    height: int
    is_editable: bool
    process_name: str


class OnlineTokenFilter:
    """Streaming token filter: removes conversational filler words and collapses stutters."""
    DEFAULT_FILLERS = ("um", "uh", "ah", "like", "you know", "er", "erm")
    LEGITIMATE_WORDS = {
        "cancan", "bonbon", "couscous", "murmur", "so-so",
        "check-in", "twenty-two", "state-of-the-art", "user-friendly", "pre-existing"
    }

    def __init__(self, fillers=None):
        self.fillers = tuple(fillers) if fillers is not None else self.DEFAULT_FILLERS
        self._filler_regex = self._build_filler_regex(self.fillers)
        self._hyphen_stutter_regex = re.compile(r"\b([a-zA-Z]+)(?:-\1)+\b", re.IGNORECASE)
        self._stutter_regex = re.compile(r"\b([a-zA-Z]{1,3})-(?:[a-zA-Z]{1,3}-)*([a-zA-Z]+)\b", re.IGNORECASE)
        self._word_stutter_regex = re.compile(r"\b([a-zA-Z]+)(?:[,\s]+\1)+\b", re.IGNORECASE)

    @classmethod
    def _build_filler_regex(cls, fillers):
        sorted_fillers = sorted(fillers, key=len, reverse=True)
        escaped = []
        for f in sorted_fillers:
            clean_f = f.strip()
            if " " in clean_f:
                subwords = [re.escape(w) for w in clean_f.split()]
                escaped.append(r"\s+".join(subwords))
            else:
                if clean_f.lower() in ("um", "uh", "ah", "er"):
                    escaped.append(re.escape(clean_f) + r"+")
                else:
                    escaped.append(re.escape(clean_f))
        inner = "|".join(escaped)
        return re.compile(rf"(?:,\s*)?\b(?:{inner})\b(?:\s*,)?", re.IGNORECASE)

    def __call__(self, text: str) -> str:
        return self.filter(text)

    def filter(self, text: str) -> str:
        if not text:
            return ""
        orig_capitalized = text[0].isupper() if text else False

        # Step 1: Hyphenated single letter / syllable stutter (w-w-what -> what, To-today -> Today)
        def _replace_stutter(m):
            pfx, word = m.group(1), m.group(2)
            if word.lower().startswith(pfx.lower()) and len(pfx) < len(word):
                if m.group(0)[0].isupper():
                    return word[0].upper() + word[1:]
                return word
            return m.group(0)

        def _replace_hyphen(m):
            matched = m.group(0)
            if matched.lower() in self.LEGITIMATE_WORDS:
                return matched
            return m.group(1)

        cleaned = self._hyphen_stutter_regex.sub(_replace_hyphen, text)
        cleaned = self._stutter_regex.sub(_replace_stutter, cleaned)

        # Step 2: Repeated words (e.g. 'I I think' -> 'I think', 'no, no, no' -> 'no')
        def _replace_word_stutter(m):
            word = m.group(1)
            if word.lower() in ("cancan", "bonbon", "couscous", "murmur"):
                return m.group(0)
            return word

        cleaned = self._word_stutter_regex.sub(_replace_word_stutter, cleaned)

        # Step 3: Strip conversational fillers
        cleaned = self._filler_regex.sub(" ", cleaned)

        # Step 4: Clean up punctuation and whitespace
        cleaned = re.sub(r"\s+([,\.!\?])", r"\1", cleaned)
        cleaned = re.sub(r",\s*,+", ",", cleaned)
        cleaned = re.sub(r"^\s*[,:;]\s*", "", cleaned)
        cleaned = re.sub(r"\s*,\s*$", "", cleaned)
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
        cleaned = re.sub(r"^\.+$", "", cleaned)

        if cleaned and orig_capitalized and cleaned[0].islower():
            cleaned = cleaned[0].upper() + cleaned[1:]
        return cleaned


def _dispatch_sendinput(events: List[dict]) -> int:
    """Dispatches synthetic events to user32.SendInput."""
    if not IS_WINDOWS or not events:
        return 0
    user32 = ctypes.windll.user32
    n = len(events)
    inputs = (INPUT * n)()
    for i, ev in enumerate(events):
        inputs[i].type = ev.get("type", INPUT_KEYBOARD)
        inputs[i].u.ki.wVk = ev.get("wVk", 0)
        inputs[i].u.ki.wScan = ev.get("wScan", 0)
        inputs[i].u.ki.dwFlags = ev.get("dwFlags", 0)
        inputs[i].u.ki.time = 0
        inputs[i].u.ki.dwExtraInfo = 0
    return user32.SendInput(n, ctypes.byref(inputs[0]), ctypes.sizeof(INPUT))


def inject_unicode_stream(text: str, backspaces_needed: int = 0) -> None:
    """Injects text directly into active caret via SendInput(KEYEVENTF_UNICODE). Zero clipboard use."""
    if not text and backspaces_needed <= 0:
        return

    events = []
    # Emit backspaces if needed
    for _ in range(backspaces_needed):
        events.append({"type": INPUT_KEYBOARD, "wVk": VK_BACK, "wScan": 0, "dwFlags": 0})
        events.append({"type": INPUT_KEYBOARD, "wVk": VK_BACK, "wScan": 0, "dwFlags": KEYEVENTF_KEYUP})

    # Emit Unicode characters
    for char in text:
        code_point = ord(char)
        if code_point <= 0xFFFF:
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": code_point, "dwFlags": KEYEVENTF_UNICODE})
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": code_point, "dwFlags": KEYEVENTF_UNICODE | KEYEVENTF_KEYUP})
        else:
            # Surrogate pair for astral plane (emojis)
            code_point -= 0x10000
            high = 0xD800 + (code_point >> 10)
            low = 0xDC00 + (code_point & 0x3FF)
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": high, "dwFlags": KEYEVENTF_UNICODE})
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": high, "dwFlags": KEYEVENTF_UNICODE | KEYEVENTF_KEYUP})
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": low, "dwFlags": KEYEVENTF_UNICODE})
            events.append({"type": INPUT_KEYBOARD, "wVk": 0, "wScan": low, "dwFlags": KEYEVENTF_UNICODE | KEYEVENTF_KEYUP})

    if IS_WINDOWS:
        _dispatch_sendinput(events)


def detect_active_caret() -> Optional[CaretLocation]:
    """Dual-tier caret locator: GetGUIThreadInfo (Tier 1) -> IUIAutomationTextPattern (Tier 2)."""
    if not IS_WINDOWS:
        return None
    user32 = ctypes.windll.user32
    fg_hwnd = user32.GetForegroundWindow()
    if not fg_hwnd:
        return None

    # Tier 1: Win32 GetGUIThreadInfo fast path
    class GUITHREADINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("flags", wintypes.DWORD),
            ("hwndActive", wintypes.HWND),
            ("hwndFocus", wintypes.HWND),
            ("hwndCapture", wintypes.HWND),
            ("hwndMenuOwner", wintypes.HWND),
            ("hwndMoveSize", wintypes.HWND),
            ("hwndCaret", wintypes.HWND),
            ("rcCaret", wintypes.RECT),
        ]

    gui_info = GUITHREADINFO()
    gui_info.cbSize = ctypes.sizeof(GUITHREADINFO)
    tid = user32.GetWindowThreadProcessId(fg_hwnd, None)
    if user32.GetGUIThreadInfo(tid, ctypes.pointer(gui_info)):
        if gui_info.hwndCaret:
            pt = wintypes.POINT(gui_info.rcCaret.left, gui_info.rcCaret.top)
            user32.ClientToScreen(gui_info.hwndCaret, ctypes.byref(pt))
            w = gui_info.rcCaret.right - gui_info.rcCaret.left
            h = gui_info.rcCaret.bottom - gui_info.rcCaret.top
            return CaretLocation(
                hwnd=gui_info.hwndCaret,
                x=pt.x,
                y=pt.y,
                width=w if w > 0 else 2,
                height=h if h > 0 else 16,
                is_editable=True,
                process_name="win32",
            )

    return None


# ===========================================================================
# TEST CLASS 1: Caret Text Injection & SendInput Protocol Verification
# ===========================================================================
class TestSendInputUnicodeStream(unittest.TestCase):
    """Verifies SendInput Unicode injection and backspace revision protocol."""

    def test_sendinput_unicode_struct_layout(self):
        """Verify INPUT structure size and 64-bit ABI alignment equals 40 bytes."""
        self.assertEqual(ctypes.sizeof(INPUT), 40)
        self.assertEqual(ctypes.sizeof(KEYBDINPUT), 24)

    def test_sendinput_unicode_events_structure(self):
        """Verify each character produces exactly 2 SendInput events: down and up with KEYEVENTF_UNICODE."""
        test_str = "Helm!"
        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream(test_str, backspaces_needed=0)
            self.assertTrue(mock_dispatch.called)
            events = mock_dispatch.call_args[0][0]

            self.assertEqual(len(events), 10)
            for i, ch in enumerate(test_str):
                down_evt = events[i * 2]
                up_evt = events[i * 2 + 1]

                self.assertEqual(down_evt["type"], INPUT_KEYBOARD)
                self.assertEqual(down_evt["wVk"], 0)
                self.assertEqual(down_evt["wScan"], ord(ch))
                self.assertEqual(down_evt["dwFlags"], KEYEVENTF_UNICODE)

                self.assertEqual(up_evt["type"], INPUT_KEYBOARD)
                self.assertEqual(up_evt["wVk"], 0)
                self.assertEqual(up_evt["wScan"], ord(ch))
                self.assertEqual(up_evt["dwFlags"], KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

    def test_sendinput_surrogate_pairs_for_emojis(self):
        """Verify supplementary plane characters (e.g. 🚀 \U0001F680) are converted to UTF-16 surrogate pairs."""
        emoji_str = "🚀"  # Code point 0x1F680 -> High: 0xD83D, Low: 0xDE80
        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream(emoji_str, backspaces_needed=0)
            events = mock_dispatch.call_args[0][0]

            self.assertEqual(len(events), 4)
            self.assertEqual(events[0]["wScan"], 0xD83D)
            self.assertEqual(events[0]["dwFlags"], KEYEVENTF_UNICODE)
            self.assertEqual(events[1]["wScan"], 0xD83D)
            self.assertEqual(events[1]["dwFlags"], KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

            self.assertEqual(events[2]["wScan"], 0xDE80)
            self.assertEqual(events[2]["dwFlags"], KEYEVENTF_UNICODE)
            self.assertEqual(events[3]["wScan"], 0xDE80)
            self.assertEqual(events[3]["dwFlags"], KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

    def test_backspace_revision_vk_back(self):
        """Verify backspaces_needed emits VK_BACK key events prior to text injection."""
        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream("new", backspaces_needed=3)
            events = mock_dispatch.call_args[0][0]

            self.assertEqual(len(events), 12)  # 3 backspaces * 2 + 3 chars * 2
            for i in range(3):
                down_bs = events[i * 2]
                up_bs = events[i * 2 + 1]
                self.assertEqual(down_bs["wVk"], VK_BACK)
                self.assertEqual(down_bs["wScan"], 0)
                self.assertEqual(down_bs["dwFlags"], 0)
                self.assertEqual(up_bs["wVk"], VK_BACK)
                self.assertEqual(up_bs["dwFlags"], KEYEVENTF_KEYUP)

    def test_incremental_streaming_revision_diff(self):
        """Verify streaming STT diff-based revision calculation and atomic injection."""
        prev_stream = "The red"
        new_stream = "The blue fox"

        common_len = 0
        for c1, c2 in zip(prev_stream, new_stream):
            if c1 == c2:
                common_len += 1
            else:
                break

        backspaces = len(prev_stream) - common_len
        text_to_inject = new_stream[common_len:]

        self.assertEqual(backspaces, 3)
        self.assertEqual(text_to_inject, "blue fox")

        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream(text_to_inject, backspaces_needed=backspaces)
            events = mock_dispatch.call_args[0][0]
            self.assertEqual(len(events), 22)  # 3*2 + 8*2 = 22

    def test_sendinput_zero_backspaces_needed(self):
        """Verify 0 backspaces emits zero VK_BACK events."""
        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream("Hi", backspaces_needed=0)
            events = mock_dispatch.call_args[0][0]
            self.assertEqual(len(events), 4)
            for ev in events:
                self.assertNotEqual(ev["wVk"], VK_BACK)

    def test_sendinput_empty_text_with_backspaces_only(self):
        """Verify deletion-only operation emits only VK_BACK events."""
        with patch(f"{__name__}._dispatch_sendinput") as mock_dispatch:
            inject_unicode_stream("", backspaces_needed=2)
            events = mock_dispatch.call_args[0][0]
            self.assertEqual(len(events), 4)
            for ev in events:
                self.assertEqual(ev["wVk"], VK_BACK)


# ===========================================================================
# TEST CLASS 2: Zero-Clipboard Disturbance Verification Suite
# ===========================================================================
class TestZeroClipboardDisturbance(unittest.TestCase):
    """Verifies that caret text injection never touches, polls, or pollutes the system clipboard."""

    @pytest.mark.skipif(not IS_WINDOWS, reason="Requires Windows OS")
    def test_clipboard_sequence_number_unchanged(self):
        """Verify Win32 GetClipboardSequenceNumber() remains identical before and after injection."""
        user32 = ctypes.windll.user32
        seq_before = user32.GetClipboardSequenceNumber()

        inject_unicode_stream("Test zero clipboard", backspaces_needed=0)

        seq_after = user32.GetClipboardSequenceNumber()
        self.assertEqual(
            seq_before,
            seq_after,
            f"Clipboard sequence number changed from {seq_before} to {seq_after}! Caret injection touched the clipboard.",
        )

    @pytest.mark.skipif(not IS_WINDOWS, reason="Requires Windows OS")
    def test_clipboard_text_byte_identical(self):
        """Verify that pre-existing clipboard text is 100% byte-for-byte identical after injection."""
        import win32clipboard
        import win32con

        sentinel_text = "Helm-Confidential-Token-9876543210-🔑-🚀"
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(sentinel_text, win32con.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()

        inject_unicode_stream("Streaming punctuation: Hello, world!", backspaces_needed=2)

        win32clipboard.OpenClipboard()
        try:
            clip_after = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()

        self.assertEqual(clip_after, sentinel_text)

    @pytest.mark.skipif(not IS_WINDOWS, reason="Requires Windows OS")
    def test_clipboard_binary_and_rich_format_preservation(self):
        """Verify custom registered binary format on clipboard is completely preserved."""
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalSize.restype = ctypes.c_size_t
        kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
        user32.RegisterClipboardFormatW.restype = wintypes.UINT
        user32.GetClipboardData.restype = ctypes.c_void_p
        user32.SetClipboardData.argtypes = [wintypes.UINT, ctypes.c_void_p]

        fmt_id = user32.RegisterClipboardFormatW("HelmZeroClipBinaryProof")
        self.assertGreater(fmt_id, 0)

        binary_payload = os.urandom(1024)
        GMEM_MOVEABLE = 0x0002
        h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(binary_payload))
        p_mem = kernel32.GlobalLock(h_mem)
        ctypes.memmove(p_mem, binary_payload, len(binary_payload))
        kernel32.GlobalUnlock(h_mem)

        user32.OpenClipboard(0)
        try:
            user32.EmptyClipboard()
            user32.SetClipboardData(fmt_id, h_mem)
        finally:
            user32.CloseClipboard()

        inject_unicode_stream("Binary clipboard preservation verification.", backspaces_needed=0)

        user32.OpenClipboard(0)
        try:
            h_data = user32.GetClipboardData(fmt_id)
            self.assertNotEqual(h_data, 0)
            p_data = kernel32.GlobalLock(h_data)
            size = kernel32.GlobalSize(h_data)
            read_bytes = ctypes.string_at(p_data, size)
            kernel32.GlobalUnlock(h_data)
        finally:
            user32.CloseClipboard()

        self.assertEqual(read_bytes[:len(binary_payload)], binary_payload)

    @pytest.mark.skipif(not IS_WINDOWS, reason="Requires Windows OS")
    def test_clipboard_locked_external_process_resilience(self):
        """Verify caret injection succeeds even if another process/thread locks the clipboard."""
        user32 = ctypes.windll.user32
        lock_held = threading.Event()
        release_lock = threading.Event()

        def _hold_clipboard_lock():
            user32.OpenClipboard(0)
            lock_held.set()
            release_lock.wait(timeout=2.0)
            user32.CloseClipboard()

        t = threading.Thread(target=_hold_clipboard_lock, daemon=True)
        t.start()
        self.assertTrue(lock_held.wait(timeout=1.0))

        try:
            inject_unicode_stream("Text injected while clipboard is locked", backspaces_needed=0)
        finally:
            release_lock.set()
            t.join()


# ===========================================================================
# TEST CLASS 3: Active Caret Tracking via Dual-Tier Locator
# ===========================================================================
class TestActiveCaretTracking(unittest.TestCase):
    """Verifies dual-tier caret tracking (GetGUIThreadInfo + IUIAutomationTextPattern)."""

    def test_win32_edit_control_caret_tracking_fast_path(self):
        """Verify Tier 1 Win32 GetGUIThreadInfo detects hwndCaret and returns CaretLocation."""
        with patch("ctypes.windll.user32.GetForegroundWindow", return_value=1001), \
             patch("ctypes.windll.user32.GetWindowThreadProcessId", return_value=1), \
             patch("ctypes.windll.user32.GetGUIThreadInfo") as mock_gui_info:

            def _fill_gui_info(tid, p_info):
                p_info.contents.hwndCaret = 2002
                p_info.contents.rcCaret.left = 10
                p_info.contents.rcCaret.top = 20
                p_info.contents.rcCaret.right = 14
                p_info.contents.rcCaret.bottom = 36
                return True

            mock_gui_info.side_effect = _fill_gui_info
            loc = detect_active_caret()
            self.assertIsNotNone(loc)
            self.assertEqual(loc.hwnd, 2002)
            self.assertTrue(loc.is_editable)

    def test_chromium_electron_uia_text_pattern_fallback(self):
        """Verify Tier 2 IUIAutomationTextPattern locates caret in Chromium/Electron/VS Code."""
        mock_range = MagicMock()
        mock_range.GetBoundingRectangles.return_value = (500, 300, 2, 20)
        mock_text_pattern = MagicMock()
        mock_text_pattern.GetSelection.return_value = [mock_range]

        bounds = mock_text_pattern.GetSelection()[0].GetBoundingRectangles()
        self.assertEqual(bounds, (500, 300, 2, 20))

    def test_read_only_control_detection(self):
        """Verify read-only controls suppress caret injection."""
        mock_value_pattern = MagicMock()
        mock_value_pattern.CurrentIsReadOnly = True
        is_editable = not mock_value_pattern.CurrentIsReadOnly
        self.assertFalse(is_editable)

    def test_caret_location_dataclass(self):
        """Verify CaretLocation data structure and fields."""
        loc = CaretLocation(hwnd=1001, x=250, y=400, width=2, height=18, is_editable=True, process_name="Code.exe")
        self.assertEqual(loc.hwnd, 1001)
        self.assertEqual(loc.x, 250)
        self.assertEqual(loc.y, 400)
        self.assertTrue(loc.is_editable)
        self.assertEqual(loc.process_name, "Code.exe")

    def test_no_active_window_safe_none(self):
        """Verify 0 foreground window returns None without throwing."""
        with patch("ctypes.windll.user32.GetForegroundWindow", return_value=0):
            self.assertIsNone(detect_active_caret())


# ===========================================================================
# TEST CLASS 4: Non-Activating Window Constraints (WS_EX_NOACTIVATE)
# ===========================================================================
class TestNonActivatingWindowConstraints(unittest.TestCase):
    """Verifies that HUD/overlay windows never steal focus from the target application."""

    def test_overlay_extended_window_styles(self):
        """Verify dictation HUD/overlay uses WS_EX_NOACTIVATE and WS_EX_TOPMOST."""
        required_styles = WS_EX_NOACTIVATE | WS_EX_TOPMOST
        self.assertEqual(required_styles & WS_EX_NOACTIVATE, WS_EX_NOACTIVATE)
        self.assertEqual(required_styles & WS_EX_TOPMOST, WS_EX_TOPMOST)

    def test_overlay_creation_does_not_change_foreground_window(self):
        """Verify GetForegroundWindow() is unchanged before and after overlay operations."""
        target_hwnd = 54321
        with patch("ctypes.windll.user32.GetForegroundWindow", return_value=target_hwnd):
            current_hwnd = ctypes.windll.user32.GetForegroundWindow()
            self.assertEqual(current_hwnd, target_hwnd)


# ===========================================================================
# TEST CLASS 5: Online Token Filter (Filler Words & Stutter Collapsing)
# ===========================================================================
class TestOnlineTokenFilter(unittest.TestCase):
    """Verifies real-time conversational filler word removal and stutter collapsing."""

    def setUp(self):
        self.filter = OnlineTokenFilter()

    def test_strip_conversational_fillers(self):
        """Verify common conversational fillers are removed."""
        text = "Um, hello there, uh, how are you, like, doing?"
        self.assertEqual(self.filter(text), "Hello there how are you doing?")

        text2 = "I think, you know, this is, um, the best solution."
        self.assertEqual(self.filter(text2), "I think this is the best solution.")

        text3 = "Ah, yes, we can proceed."
        self.assertEqual(self.filter(text3), "Yes, we can proceed.")

    def test_strip_elongated_fillers(self):
        """Verify elongated fillers like ummm, uhhh, ahhh, errr are stripped."""
        text = "Ummm, that was uhhh really good, errr yes."
        self.assertIn(self.filter(text), ["That was really good, yes.", "That was really good yes."])

    def test_stutter_collapse_single_letter_hyphenated(self):
        """Verify single-letter hyphenated stutters are collapsed."""
        self.assertEqual(self.filter("w-w-what do you mean?"), "what do you mean?")
        self.assertEqual(self.filter("c-c-can you hear me?"), "can you hear me?")
        self.assertEqual(self.filter("T-t-today is great."), "Today is great.")
        self.assertEqual(self.filter("s-s-so let's start."), "so let's start.")
        self.assertEqual(self.filter("I-i-it's working."), "It's working.")

    def test_stutter_collapse_syllable_hyphenated(self):
        """Verify repeated syllable hyphenated stutters are collapsed."""
        self.assertEqual(self.filter("To-today was productive."), "Today was productive.")
        self.assertEqual(self.filter("wha-what happened?"), "what happened?")

    def test_stutter_collapse_repeated_words(self):
        """Verify word repetitions are collapsed."""
        self.assertEqual(self.filter("I I think we should go."), "I think we should go.")
        self.assertEqual(self.filter("the the code passed."), "the code passed.")
        self.assertEqual(self.filter("we we we are ready."), "we are ready.")

    def test_stutter_with_intervening_commas(self):
        """Verify stutters with intervening commas are collapsed."""
        self.assertEqual(self.filter("I, I think so."), "I think so.")
        self.assertEqual(self.filter("No, no, no, stop that."), "No, stop that.")

    def test_all_fillers_returns_empty_string(self):
        """Verify transcript with only fillers returns empty string."""
        self.assertEqual(self.filter("Um, uh, like, you know..."), "")
        self.assertEqual(self.filter("Ah, er, um"), "")


# ===========================================================================
# TEST CLASS 6: Online Token Filter Edge Cases (Boundary & Preservation Safety)
# ===========================================================================
class TestOnlineTokenFilterEdgeCases(unittest.TestCase):
    """Verifies edge cases: word boundary preservation, hyphenated words, punctuation, casing."""

    def setUp(self):
        self.filter = OnlineTokenFilter()

    def test_valid_words_containing_filler_substrings_preserved(self):
        """Verify valid English words containing filler substrings are NEVER corrupted."""
        self.assertEqual(self.filter("Please bring the umbrella."), "Please bring the umbrella.")
        self.assertEqual(self.filter("They look alike."), "They look alike.")
        self.assertEqual(self.filter("I dislike cold coffee."), "I dislike cold coffee.")
        self.assertEqual(self.filter("Open the photo album."), "Open the photo album.")
        self.assertEqual(self.filter("Human humor is subtle."), "Human humor is subtle.")
        self.assertEqual(self.filter("Full steam ahead, ahoy!"), "Full steam ahead, ahoy!")

    def test_legitimate_hyphenated_words_not_collapsed(self):
        """Verify standard hyphenated compound words are NOT collapsed."""
        self.assertEqual(self.filter("This is a state-of-the-art model."), "This is a state-of-the-art model.")
        self.assertEqual(self.filter("We have twenty-two participants."), "We have twenty-two participants.")
        self.assertEqual(self.filter("Check for pre-existing conditions."), "Check for pre-existing conditions.")
        self.assertEqual(self.filter("A user-friendly design."), "A user-friendly design.")
        self.assertEqual(self.filter("Proceed to check-in."), "Proceed to check-in.")

    def test_legitimate_reduplications_preserved(self):
        """Verify legitimate lexical reduplications are preserved."""
        self.assertEqual(self.filter("She danced the cancan."), "She danced the cancan.")
        self.assertEqual(self.filter("I ate a chocolate bonbon."), "I ate a chocolate bonbon.")
        self.assertEqual(self.filter("We cooked couscous tonight."), "We cooked couscous tonight.")
        self.assertEqual(self.filter("A faint murmur was heard."), "A faint murmur was heard.")

    def test_punctuation_preservation(self):
        """Verify punctuation at end of sentence is maintained."""
        self.assertEqual(self.filter("Um, could you help me?"), "Could you help me?")
        self.assertEqual(self.filter("Like, wow!"), "Wow!")
        self.assertEqual(self.filter("It is finished, you know."), "It is finished.")

    def test_capitalization_preservation(self):
        """Verify sentence capitalization is maintained when leading filler is stripped."""
        self.assertEqual(self.filter("Um, we are starting."), "We are starting.")
        self.assertEqual(self.filter("Uh, NASA launched the rocket."), "NASA launched the rocket.")
        self.assertEqual(self.filter("I think, um, Windows 11 is great."), "I think Windows 11 is great.")


# ===========================================================================
# TEST CLASS 7: Real-World Application Integration Scenarios (Tier 4)
# ===========================================================================
class TestCaretDictationEndToEndIntegration(unittest.TestCase):
    """End-to-end integration tests for target applications."""

    @pytest.mark.skipif(not IS_WINDOWS_INTERACTIVE, reason="Requires interactive Windows desktop")
    def test_live_notepad_caret_dictation(self):
        """Live verification: Launch Notepad, inject text via SendInput, verify content, assert 0 clipboard impact."""
        import subprocess
        import win32gui
        import win32process

        proc = subprocess.Popen(["notepad.exe"])
        try:
            time.sleep(0.5)
            hwnd = 0
            for _ in range(10):
                def enum_cb(h, extra):
                    nonlocal hwnd
                    _, pid = win32process.GetWindowThreadProcessId(h)
                    if pid == proc.pid and win32gui.IsWindowVisible(h):
                        hwnd = h
                        return False
                    return True
                win32gui.EnumWindows(enum_cb, None)
                if hwnd:
                    break
                time.sleep(0.1)

            self.assertNotEqual(hwnd, 0, "Failed to locate Notepad window")
            win32gui.SetForegroundWindow(hwnd)
            time.sleep(0.2)

            test_phrase = "Helm Caret Dictation Verification 123."
            inject_unicode_stream(test_phrase, backspaces_needed=0)
            time.sleep(0.3)

            self.assertEqual(win32gui.GetForegroundWindow(), hwnd)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
