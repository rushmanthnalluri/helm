"""tests/test_batch19_hud.py - Batch 19A Acceptance Tests.

Verifies:
  1. Multi-monitor virtual screen bounds calculation.
  2. Overlay creation with WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TOPMOST.
  3. Screen capture exclusion via SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE).
  4. Target bounding box and status text state updates.
  5. Clean lifecycle management (show, hide, destroy).
"""

import sys
import os
import unittest
import ctypes
from ctypes import wintypes

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_hud
from helm_hud import (
    HelmHardwareHUD, WS_EX_TOPMOST, WS_EX_TRANSPARENT,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WDA_EXCLUDEFROMCAPTURE
)

user32 = ctypes.windll.user32


class TestBatch19HardwareHUD(unittest.TestCase):

    def test_virtual_screen_bounds(self):
        """Verifies multi-monitor virtual screen dimensions are positive and non-zero."""
        x, y, w, h = HelmHardwareHUD.get_virtual_screen_bounds()
        self.assertGreater(w, 0, "Virtual screen width must be positive")
        self.assertGreater(h, 0, "Virtual screen height must be positive")

    def test_overlay_creation_and_window_styles(self):
        """Verifies window styles match click-through, topmost, layered, and no-activate requirements."""
        hud = HelmHardwareHUD()
        hwnd = hud.create_overlay()
        self.assertIsNotNone(hwnd, "HUD HWND must be valid")

        try:
            # Query extended window styles
            GWL_EXSTYLE = -20
            GetWindowLongW = user32.GetWindowLongW
            GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
            GetWindowLongW.restype = wintypes.LONG

            ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE)

            # Assert all 4 critical style flags are present
            self.assertTrue(ex_style & WS_EX_TOPMOST, "HUD must have WS_EX_TOPMOST")
            self.assertTrue(ex_style & WS_EX_TRANSPARENT, "HUD must have WS_EX_TRANSPARENT (click-through)")
            self.assertTrue(ex_style & WS_EX_LAYERED, "HUD must have WS_EX_LAYERED")
            self.assertTrue(ex_style & WS_EX_NOACTIVATE, "HUD must have WS_EX_NOACTIVATE (no focus stealing)")
        finally:
            hud.destroy()

    def test_screen_capture_exclusion_affinity(self):
        """Verifies SetWindowDisplayAffinity sets WDA_EXCLUDEFROMCAPTURE."""
        hud = HelmHardwareHUD()
        hwnd = hud.create_overlay()
        try:
            ok = hud.set_capture_exclusion(True)
            self.assertTrue(ok, "SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) should succeed on Windows 10+")

            # Query affinity back
            affinity = wintypes.DWORD()
            GetWindowDisplayAffinity = user32.GetWindowDisplayAffinity
            GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            GetWindowDisplayAffinity.restype = wintypes.BOOL

            res = GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity))
            self.assertTrue(res)
            self.assertEqual(affinity.value, WDA_EXCLUDEFROMCAPTURE)
        finally:
            hud.destroy()

    def test_target_box_and_status_update(self):
        """Verifies target bounding box and status updates cleanly."""
        hud = HelmHardwareHUD()
        hud.create_overlay()
        try:
            hud.set_target_box(100, 150, 300, 200, "HELM: SNAP_WINDOW (calc)")
            self.assertEqual(hud.target_box, (100, 150, 300, 200))
            self.assertEqual(hud.status_text, "HELM: SNAP_WINDOW (calc)")

            hud.show()
            self.assertTrue(hud.is_visible)

            hud.hide()
            self.assertFalse(hud.is_visible)
        finally:
            hud.destroy()


if __name__ == "__main__":
    unittest.main()
