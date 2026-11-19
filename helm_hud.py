"""helm_hud.py - Batch 19A: Multi-Monitor Transparent Hardware HUD Overlay.

Architectural Guarantees:
  1. Display-Only: Zero input hooks, zero keyboard/mouse interception.
  2. Click-Through & Non-Activating:
     WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST.
     Never steals focus; all mouse clicks pass directly through to background applications.
  3. Screen Capture Exclusion:
     SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) ensures screenshots, screen recordings,
     and vision model inputs never see the overlay, avoiding visual feedback corruption.
  4. Multi-Monitor Spanning:
     Queries SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN
     to cover all connected monitors seamlessly.
"""

import sys
import ctypes
from ctypes import wintypes
from typing import Optional, Tuple, Dict, Any

# Win32 Constants
WS_POPUP = 0x80000000
WS_VISIBLE = 0x10000000

WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000

LWA_COLORKEY = 0x00000001
LWA_ALPHA = 0x00000002

WDA_NONE = 0x00000000
WDA_MONITOR = 0x00000001
WDA_EXCLUDEFROMCAPTURE = 0x00000011

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = ctypes.c_longlong if sys.maxsize > 2**32 else ctypes.c_long

user32.RegisterClassExW.argtypes = [ctypes.c_void_p]
user32.RegisterClassExW.restype = wintypes.ATOM

user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
]
user32.CreateWindowExW.restype = wintypes.HWND

user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
user32.SetWindowDisplayAffinity.restype = wintypes.BOOL

user32.SetLayeredWindowAttributes.argtypes = [wintypes.HWND, wintypes.COLORREF, wintypes.BYTE, wintypes.DWORD]
user32.SetLayeredWindowAttributes.restype = wintypes.BOOL

user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL

user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong if sys.maxsize > 2**32 else ctypes.c_long,
                             wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


@WNDPROC
def _global_hud_wndproc(hwnd: int, msg: int, wparam: int, lparam: int):
    WM_DESTROY = 0x0002
    if msg == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0
    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HICON),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class HelmHardwareHUD:
    """Multi-Monitor transparent click-through HUD overlay excluded from screen captures."""

    CLASS_NAME = "HelmHardwareHUDOverlayClass"
    _CLASS_REGISTERED = False

    def __init__(self):
        self.hwnd: Optional[int] = None
        self.target_box: Optional[Tuple[int, int, int, int]] = None  # (x, y, w, h)
        self.status_text: str = "HELM: ARMED"
        self.color_key = 0x00000000  # Black is transparent key
        self.is_visible = False
        self.screen_bounds = self.get_virtual_screen_bounds()

    @staticmethod
    def get_virtual_screen_bounds() -> Tuple[int, int, int, int]:
        """Returns (x, y, width, height) spanning all attached monitors."""
        x = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        y = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        cx = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        cy = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        return x, y, cx, cy

    def create_overlay(self) -> int:
        """Creates the hardware HUD window with click-through and screen capture exclusion."""
        hinst = kernel32.GetModuleHandleW(None)

        if not HelmHardwareHUD._CLASS_REGISTERED:
            wcex = WNDCLASSEXW()
            wcex.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wcex.style = 0
            wcex.lpfnWndProc = _global_hud_wndproc
            wcex.cbClsExtra = 0
            wcex.cbWndExtra = 0
            wcex.hInstance = hinst
            wcex.hIcon = None
            wcex.hCursor = None
            wcex.hbrBackground = gdi32.GetStockObject(4)  # BLACK_BRUSH (transparent color key)
            wcex.lpszMenuName = None
            wcex.lpszClassName = self.CLASS_NAME
            wcex.hIconSm = None

            user32.RegisterClassExW(ctypes.byref(wcex))
            HelmHardwareHUD._CLASS_REGISTERED = True

        ex_style = (
            WS_EX_TOPMOST
            | WS_EX_TRANSPARENT
            | WS_EX_LAYERED
            | WS_EX_NOACTIVATE
        )
        style = WS_POPUP

        x, y, w, h = self.screen_bounds

        self.hwnd = user32.CreateWindowExW(
            ex_style,
            self.CLASS_NAME,
            "Helm Visual Overlay",
            style,
            x, y, w, h,
            None,
            None,
            hinst,
            None
        )

        if not self.hwnd:
            raise ctypes.WinError()

        # Set transparency: Black (0x00000000) is 100% transparent click-through
        user32.SetLayeredWindowAttributes(self.hwnd, self.color_key, 255, LWA_COLORKEY)

        # Exclude from screen capture (SetWindowDisplayAffinity)
        self.set_capture_exclusion(True)

        return self.hwnd

    def set_capture_exclusion(self, exclude: bool = True) -> bool:
        """Toggles WDA_EXCLUDEFROMCAPTURE to exclude HUD from screen captures."""
        if not self.hwnd:
            return False
        affinity = WDA_EXCLUDEFROMCAPTURE if exclude else WDA_NONE
        res = user32.SetWindowDisplayAffinity(self.hwnd, affinity)
        return bool(res)

    def set_target_box(self, x: int, y: int, w: int, h: int, status_text: str = ""):
        """Sets the active target highlight bounding box and status pill text."""
        self.target_box = (x, y, w, h)
        if status_text:
            self.status_text = status_text
        if self.hwnd:
            user32.InvalidateRect(self.hwnd, None, True)

    def show(self):
        if self.hwnd:
            user32.ShowWindow(self.hwnd, 5)  # SW_SHOW
            self.is_visible = True

    def hide(self):
        if self.hwnd:
            user32.ShowWindow(self.hwnd, 0)  # SW_HIDE
            self.is_visible = False

    def destroy(self):
        if self.hwnd:
            user32.DestroyWindow(self.hwnd)
            self.hwnd = None
            self.is_visible = False
