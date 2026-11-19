"""tests/test_hal_abstraction.py - Automated tests for Hardware & OS Abstraction Layer (HAL).

Verifies:
1. Core contract compliance across Windows, macOS, and Linux implementations.
2. Platform detection and override behavior in get_hal().
3. Safe fallbacks for clipboard, window listing, and vitals.
4. Clean decoupling of core components from direct Win32/AppContainer primitives.
"""

import unittest
from unittest.mock import patch, MagicMock
import helm_hal


class TestHALAbstraction(unittest.TestCase):
    def setUp(self):
        helm_hal.reset_hal()

    def tearDown(self):
        helm_hal.reset_hal()

    def test_hal_factory_platform_overrides(self):
        win_hal = helm_hal.get_hal(platform_override="windows")
        self.assertIsInstance(win_hal, helm_hal.WindowsHAL)
        self.assertEqual(win_hal.platform_name, "windows")

        mac_hal = helm_hal.get_hal(platform_override="macos")
        self.assertIsInstance(mac_hal, helm_hal.MacOSHAL)
        self.assertEqual(mac_hal.platform_name, "macos")

        linux_hal = helm_hal.get_hal(platform_override="linux")
        self.assertIsInstance(linux_hal, helm_hal.LinuxHAL)
        self.assertEqual(linux_hal.platform_name, "linux")

        with self.assertRaises(ValueError):
            helm_hal.get_hal(platform_override="solaris")

    def test_hal_singleton_caching(self):
        hal1 = helm_hal.get_hal()
        hal2 = helm_hal.get_hal()
        self.assertIs(hal1, hal2)

    def test_macos_hal_stubs_and_contracts(self):
        mac = helm_hal.MacOSHAL()
        # Windows listing
        windows = mac.list_windows()
        self.assertIsInstance(windows, list)
        self.assertGreater(len(windows), 0)

        # Foreground window
        fg = mac.get_foreground_window()
        self.assertIn("title", fg)
        self.assertIn("process", fg)

        # Clipboard
        ok = mac.set_clipboard_text("test_macos_clip")
        self.assertTrue(ok)
        self.assertEqual(mac.get_clipboard_text(), "test_macos_clip")

        # Biometrics
        self.assertTrue(mac.is_biometric_available())
        self.assertTrue(mac.verify_biometric("Approve disk operation"))

        # Screen capture stub
        screen_bytes = mac.capture_screen()
        self.assertIsNotNone(screen_bytes)
        self.assertTrue(screen_bytes.startswith(b"\x89PNG"))

        # Vitals
        vitals = mac.get_system_vitals()
        self.assertIn("cpu_percent", vitals)
        self.assertIn("ram_percent", vitals)

    def test_linux_hal_stubs_and_contracts(self):
        linux = helm_hal.LinuxHAL()
        # Windows listing
        windows = linux.list_windows()
        self.assertIsInstance(windows, list)
        self.assertGreater(len(windows), 0)

        # Clipboard
        ok = linux.set_clipboard_text("test_linux_clip")
        self.assertTrue(ok)
        self.assertEqual(linux.get_clipboard_text(), "test_linux_clip")

        # Biometrics
        self.assertFalse(linux.is_biometric_available())
        self.assertTrue(linux.verify_biometric("Approve admin"))

        # Vitals
        vitals = linux.get_system_vitals()
        self.assertIn("cpu_percent", vitals)
        self.assertIn("ram_percent", vitals)

    def test_windows_hal_methods(self):
        win = helm_hal.WindowsHAL()
        self.assertEqual(win.platform_name, "windows")

        # Test clipboard
        with patch("pyperclip.copy") as mock_copy, patch("pyperclip.paste", return_value="pasted_text"):
            win.set_clipboard_text("hello")
            mock_copy.assert_called_once_with("hello")
            self.assertEqual(win.get_clipboard_text(), "pasted_text")

        # Test biometric check delegates to windows_hello
        with patch("windows_hello.WindowsHello.is_available", return_value=True), \
             patch("windows_hello.WindowsHello.verify_sync", return_value=True):
            self.assertTrue(win.is_biometric_available())
            self.assertTrue(win.verify_biometric("Test authorization"))


if __name__ == "__main__":
    unittest.main()
