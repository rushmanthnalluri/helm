"""tests/test_os_hal.py - Comprehensive Unit Tests for Hardware & OS Abstraction Layer (HAL).

Covers:
1. Interface compliance: IWindowManager, INotificationManager, IBiometrics,
   ISystemVitals, IClipboardManager, IInputSimulator, BaseHAL.
2. Platform dispatch and auto-detection factory (get_hal, set_hal, reset_hal).
3. MockHAL deterministic headless simulation (all subsystems).
4. DarwinHAL / MacOSHAL implementation, AppleScript/Touch ID stubs.
5. LinuxHAL implementation, xdotool/dbus/procfs stubs.
6. WindowsHAL native Win32/WinRT implementation and safe fallbacks.
7. Cross-platform isolation without hard dependencies on win32gui/winrt.
"""

from __future__ import annotations

import inspect
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import helm_hal
from helm_hal import (
    BaseHAL,
    DarwinHAL,
    IBiometrics,
    IClipboardManager,
    IInputSimulator,
    INotificationManager,
    ISystemVitals,
    IWindowManager,
    LinuxHAL,
    MacOSHAL,
    MockHAL,
    WindowsHAL,
    get_hal,
    reset_hal,
    set_hal,
)


class TestInterfaceCompliance(unittest.TestCase):
    """Verifies interface contracts, abstract base classes, and inheritance."""

    def test_abstract_interfaces_cannot_be_instantiated(self):
        """Abstract interfaces must not be directly instantiable."""
        for interface in (
            IWindowManager,
            INotificationManager,
            IBiometrics,
            ISystemVitals,
            IClipboardManager,
            IInputSimulator,
            BaseHAL,
        ):
            with self.assertRaises(TypeError):
                interface()

    def test_all_implementations_inherit_all_interfaces(self):
        """All HAL implementations must implement every subsystem interface."""
        implementations = [WindowsHAL, DarwinHAL, MacOSHAL, LinuxHAL, MockHAL]
        interfaces = [
            IWindowManager,
            INotificationManager,
            IBiometrics,
            ISystemVitals,
            IClipboardManager,
            IInputSimulator,
            BaseHAL,
        ]

        for impl in implementations:
            for iface in interfaces:
                self.assertTrue(
                    issubclass(impl, iface),
                    f"{impl.__name__} does not implement {iface.__name__}",
                )

    def test_modular_manager_properties_exposed(self):
        """BaseHAL instances must expose modular manager properties conforming to interfaces."""
        mock = MockHAL()
        self.assertIsInstance(mock.window_manager, IWindowManager)
        self.assertIsInstance(mock.notification_manager, INotificationManager)
        self.assertIsInstance(mock.biometrics, IBiometrics)
        self.assertIsInstance(mock.vitals, ISystemVitals)
        self.assertIsInstance(mock.clipboard, IClipboardManager)
        self.assertIsInstance(mock.input_simulator, IInputSimulator)


class TestPlatformDispatchFactory(unittest.TestCase):
    """Verifies factory dispatch, platform detection, overrides, and singleton lifecycle."""

    def setUp(self):
        reset_hal()

    def tearDown(self):
        reset_hal()

    def test_get_hal_platform_overrides(self):
        """Explicit platform_override values return corresponding HALs."""
        win = get_hal(platform_override="windows")
        self.assertIsInstance(win, WindowsHAL)
        self.assertEqual(win.platform_name, "windows")

        win32 = get_hal(platform_override="win32")
        self.assertIsInstance(win32, WindowsHAL)

        darwin = get_hal(platform_override="darwin")
        self.assertIsInstance(darwin, DarwinHAL)
        self.assertEqual(darwin.platform_name, "darwin")

        macos = get_hal(platform_override="macos")
        self.assertIsInstance(macos, MacOSHAL)
        self.assertIsInstance(macos, DarwinHAL)
        self.assertEqual(macos.platform_name, "macos")

        mac = get_hal(platform_override="mac")
        self.assertIsInstance(mac, MacOSHAL)

        linux = get_hal(platform_override="linux")
        self.assertIsInstance(linux, LinuxHAL)
        self.assertEqual(linux.platform_name, "linux")

        mock = get_hal(platform_override="mock")
        self.assertIsInstance(mock, MockHAL)
        self.assertEqual(mock.platform_name, "mock")

        headless = get_hal(platform_override="headless")
        self.assertIsInstance(headless, MockHAL)

        test_mock = get_hal(platform_override="test")
        self.assertIsInstance(test_mock, MockHAL)

    def test_unknown_platform_override_raises_value_error(self):
        """Unknown platform override strings must raise ValueError."""
        with self.assertRaises(ValueError):
            get_hal(platform_override="amiga_os")

    def test_singleton_caching_and_reset(self):
        """get_hal() returns the cached singleton until reset_hal() is called."""
        h1 = get_hal()
        h2 = get_hal()
        self.assertIs(h1, h2)

        reset_hal()
        h3 = get_hal()
        self.assertIsNot(h1, h3)

    def test_set_hal_custom_injection(self):
        """set_hal() allows injecting a customized HAL instance."""
        custom = MockHAL()
        custom.clipboard_content = "custom_injected"
        set_hal(custom)

        self.assertIs(get_hal(), custom)
        self.assertEqual(get_hal().get_text(), "custom_injected")

        with self.assertRaises(TypeError):
            set_hal("not_a_hal")  # type: ignore

    def test_auto_detection_by_sys_platform(self):
        """Dynamic detection chooses implementation based on sys.platform."""
        with patch.object(sys, "platform", "win32"):
            reset_hal()
            hal = get_hal()
            self.assertIsInstance(hal, WindowsHAL)

        with patch.object(sys, "platform", "darwin"):
            reset_hal()
            hal = get_hal()
            self.assertIsInstance(hal, DarwinHAL)

        with patch.object(sys, "platform", "linux"):
            reset_hal()
            hal = get_hal()
            self.assertIsInstance(hal, LinuxHAL)

        with patch.object(sys, "platform", "freebsd13"):
            reset_hal()
            hal = get_hal()
            self.assertIsInstance(hal, (LinuxHAL, MockHAL))

    def test_environment_override_forces_mock(self):
        """HELM_HAL_BACKEND=mock forces MockHAL even if sys.platform is win32."""
        with patch.dict(os.environ, {"HELM_HAL_BACKEND": "mock"}):
            reset_hal()
            hal = get_hal()
            self.assertIsInstance(hal, MockHAL)


class TestMockHALSimulation(unittest.TestCase):
    """Comprehensive verification of MockHAL behavior across all subsystems."""

    def setUp(self):
        self.hal = MockHAL()

    # --- Window Manager ---

    def test_window_manager_basics(self):
        # Default active window
        active = self.hal.get_active_window()
        self.assertEqual(active["title"], "Helm Dashboard")
        self.assertEqual(self.hal.get_active_window_title(), "Helm Dashboard")
        self.assertEqual(self.hal.get_active_window_class(), "HelmUI")

        # Listing windows
        windows = self.hal.list_windows()
        self.assertEqual(len(windows), 3)

        # Adding dynamic mock window
        new_win = self.hal.add_mock_window(
            title="Calculator",
            class_name="CalcFrame",
            pid=5555,
            rect={"x": 50, "y": 50, "w": 400, "h": 500},
        )
        self.assertEqual(new_win["title"], "Calculator")
        self.assertEqual(len(self.hal.list_windows()), 4)

    def test_window_focus_and_actions(self):
        # Focus by title substring
        ok = self.hal.focus_window("Chrome")
        self.assertTrue(ok)
        self.assertEqual(self.hal.get_active_window_title(), "Google Chrome")
        self.assertEqual(self.hal.window_actions[-1], ("focus", "Chrome"))

        # Focus by handle
        ok = self.hal.focus_window(1002)
        self.assertTrue(ok)
        self.assertEqual(self.hal.get_active_window_title(), "Visual Studio Code")

        # Focus nonexistent returns False
        self.assertFalse(self.hal.focus_window("NonexistentApp"))

        # Minimize, maximize, snap
        self.assertTrue(self.hal.minimize_window())
        self.assertEqual(self.hal.window_actions[-1], ("minimize", None))

        self.assertTrue(self.hal.maximize_window(1001))
        self.assertEqual(self.hal.window_actions[-1], ("maximize", 1001))

        self.assertTrue(self.hal.snap_window("left"))
        self.assertEqual(self.hal.window_actions[-1], ("snap", "left"))

        # Backward compatibility alias
        fg = self.hal.get_foreground_window()
        self.assertEqual(fg["title"], self.hal.get_active_window_title())

    # --- Notifications ---

    def test_notification_manager(self):
        self.hal.post_notification(
            title="Update Available",
            message="Helm v2.1 is ready to install.",
            app_name="HelmUpdater",
            icon_path="/icons/update.png",
        )
        self.assertEqual(len(self.hal.notifications), 1)
        notif = self.hal.notifications[0]
        self.assertEqual(notif["title"], "Update Available")
        self.assertEqual(notif["message"], "Helm v2.1 is ready to install.")
        self.assertEqual(notif["app_name"], "HelmUpdater")
        self.assertEqual(notif["icon_path"], "/icons/update.png")
        self.assertIn("timestamp", notif)

        # Backward-compatibility alias
        self.hal.show_notification(title="Alert", message="Disk space low")
        self.assertEqual(len(self.hal.notifications), 2)
        self.assertEqual(self.hal.notifications[1]["title"], "Alert")

    # --- Biometrics ---

    def test_biometrics_simulation(self):
        # Default state: available and passes
        self.assertTrue(self.hal.is_available())
        self.assertTrue(self.hal.authenticate("Authenticate for admin task"))
        self.assertEqual(self.hal.biometric_calls, ["Authenticate for admin task"])

        # Configure availability and failure
        self.hal.set_biometric_available(False)
        self.assertFalse(self.hal.is_available())
        self.assertFalse(self.hal.is_biometric_available())

        self.hal.set_biometric_result(False)
        self.assertFalse(self.hal.authenticate("Reason 2"))
        self.assertFalse(self.hal.verify_biometric("Reason 3"))
        self.assertEqual(len(self.hal.biometric_calls), 3)

    # --- System Vitals ---

    def test_vitals_querying_and_configuration(self):
        # Default vitals
        self.assertEqual(self.hal.get_cpu_usage(), 12.0)
        mem = self.hal.get_memory_usage()
        self.assertEqual(mem["total_gb"], 32.0)
        self.assertEqual(mem["avail_gb"], 16.0)

        bat = self.hal.get_battery_status()
        self.assertEqual(bat["percent"], 90)
        self.assertTrue(bat["power_plugged"])

        disk = self.hal.get_disk_usage()
        self.assertEqual(disk["total_gb"], 1024.0)

        vitals = self.hal.get_system_vitals()
        self.assertEqual(vitals["cpu_percent"], 12.0)
        self.assertEqual(vitals["ram_percent"], 50.0)
        self.assertEqual(vitals["ram_avail_gb"], 16.0)
        self.assertEqual(vitals["disk_free_gb"], 512.0)
        self.assertEqual(vitals["battery_percent"], 90)

        # Dynamic configuration
        self.hal.set_vitals(
            cpu=85.5,
            mem={"total_gb": 64.0, "avail_gb": 8.0, "used_gb": 56.0, "percent": 87.5},
            battery={"percent": 15, "power_plugged": False, "status": "15% (On battery)"},
            disk={"total_gb": 2048.0, "free_gb": 256.0, "used_gb": 1792.0, "percent": 87.5},
        )
        self.assertEqual(self.hal.get_cpu_usage(), 85.5)
        self.assertEqual(self.hal.get_memory_usage()["percent"], 87.5)
        self.assertEqual(self.hal.get_battery_status()["percent"], 15)
        self.assertEqual(self.hal.get_disk_usage()["total_gb"], 2048.0)

    # --- Clipboard ---

    def test_clipboard_management(self):
        self.assertEqual(self.hal.get_text(), "")
        self.assertTrue(self.hal.set_text("Hello clipboard!"))
        self.assertEqual(self.hal.get_text(), "Hello clipboard!")

        # Unicode handling
        self.assertTrue(self.hal.set_clipboard_text("Helm 🚀 现代桌面"))
        self.assertEqual(self.hal.get_clipboard_text(), "Helm 🚀 现代桌面")

    # --- Input Simulator ---

    def test_input_simulator(self):
        self.assertTrue(self.hal.type_text("echo 'test'"))
        self.assertEqual(self.hal.typed_inputs, ["echo 'test'"])

        self.assertTrue(self.hal.send_input_text("second line"))
        self.assertEqual(self.hal.typed_inputs[-1], "second line")

        self.assertTrue(self.hal.send_hotkey("ctrl", "shift", "p"))
        self.assertEqual(self.hal.hotkey_inputs, [("ctrl", "shift", "p")])

        self.assertTrue(self.hal.press_key("enter"))
        self.assertEqual(self.hal.pressed_keys, ["enter"])

    # --- Generic Screen / URL ---

    def test_screen_capture_and_open_url(self):
        capture = self.hal.capture_screen()
        self.assertIsNotNone(capture)
        self.assertTrue(capture.startswith(b"\x89PNG"))

        self.assertTrue(self.hal.open_url("https://github.com/helm/helm"))
        self.assertEqual(self.hal.opened_urls, ["https://github.com/helm/helm"])


class TestDarwinHAL(unittest.TestCase):
    """Verifies DarwinHAL / MacOSHAL contracts, stubs, and platform details."""

    def setUp(self):
        self.darwin = DarwinHAL()
        self.macos = MacOSHAL()

    def test_platform_identifiers(self):
        self.assertEqual(self.darwin.platform_name, "darwin")
        self.assertEqual(self.macos.platform_name, "macos")
        self.assertIsInstance(self.macos, DarwinHAL)

    def test_window_manager_methods(self):
        win = self.darwin.get_active_window()
        self.assertIn("title", win)
        self.assertIn("class", win)
        self.assertIn("process", win)

        title = self.darwin.get_active_window_title()
        self.assertIsInstance(title, str)

        cls_name = self.darwin.get_active_window_class()
        self.assertIsInstance(cls_name, str)

        windows = self.darwin.list_windows()
        self.assertGreater(len(windows), 0)

        self.assertTrue(self.darwin.focus_window("Terminal"))
        self.assertTrue(self.darwin.minimize_window())
        self.assertTrue(self.darwin.maximize_window())
        self.assertTrue(self.darwin.snap_window("right"))

    def test_touch_id_biometrics(self):
        self.assertTrue(self.darwin.is_available())
        self.assertTrue(self.darwin.authenticate("Reason"))
        self.assertTrue(self.darwin.is_biometric_available())
        self.assertTrue(self.darwin.verify_biometric("Reason"))

        # Test mock override via environment variable
        with patch.dict(os.environ, {"HELM_MOCK_TOUCH_ID": "0"}):
            self.assertFalse(self.darwin.is_available())
            self.assertFalse(self.darwin.authenticate("Reason"))

    def test_vitals_querying(self):
        cpu = self.darwin.get_cpu_usage()
        self.assertIsInstance(cpu, float)

        mem = self.darwin.get_memory_usage()
        self.assertIn("total_gb", mem)
        self.assertIn("percent", mem)

        bat = self.darwin.get_battery_status()
        self.assertIn("status", bat)

        disk = self.darwin.get_disk_usage()
        self.assertIn("free_gb", disk)

        vitals = self.darwin.get_system_vitals()
        self.assertIn("cpu_percent", vitals)
        self.assertIn("ram_percent", vitals)
        self.assertIn("disk_free_gb", vitals)

    def test_clipboard_fallback(self):
        # In non-macOS environment, pbcopy will gracefully fall back to internal buffer
        ok = self.darwin.set_text("test_darwin_clip")
        self.assertTrue(ok)
        self.assertEqual(self.darwin.get_text(), "test_darwin_clip")

    def test_notifications_and_input(self):
        # Graceful execution in any environment
        self.darwin.post_notification("Test", "Darwin Notification")
        self.darwin.show_notification("Test", "Darwin Notification")
        self.darwin.type_text("hello")
        self.darwin.send_hotkey("cmd", "space")
        self.darwin.press_key("return")

    def test_screen_capture(self):
        data = self.darwin.capture_screen()
        self.assertIsNotNone(data)
        self.assertTrue(data.startswith(b"\x89PNG"))


class TestLinuxHAL(unittest.TestCase):
    """Verifies LinuxHAL contracts, xdotool/procfs stubs, and behaviors."""

    def setUp(self):
        self.linux = LinuxHAL()

    def test_platform_identifier(self):
        self.assertEqual(self.linux.platform_name, "linux")

    def test_window_manager_methods(self):
        win = self.linux.get_active_window()
        self.assertIn("title", win)
        self.assertIn("class", win)

        title = self.linux.get_active_window_title()
        self.assertIsInstance(title, str)

        cls_name = self.linux.get_active_window_class()
        self.assertIsInstance(cls_name, str)

        windows = self.linux.list_windows()
        self.assertGreater(len(windows), 0)

        self.assertTrue(self.linux.focus_window("firefox"))
        self.assertTrue(self.linux.minimize_window())
        self.assertTrue(self.linux.maximize_window())
        self.assertTrue(self.linux.snap_window("left"))

    def test_biometrics(self):
        # Hardware biometrics default to False on generic Linux
        self.assertFalse(self.linux.is_available())
        self.assertTrue(self.linux.authenticate("Admin access"))

        with patch.dict(os.environ, {"HELM_MOCK_POLKIT": "1"}):
            self.assertTrue(self.linux.is_available())
            self.assertTrue(self.linux.authenticate("Polkit reason"))

    def test_vitals_querying(self):
        cpu = self.linux.get_cpu_usage()
        self.assertIsInstance(cpu, float)

        mem = self.linux.get_memory_usage()
        self.assertIn("total_gb", mem)
        self.assertIn("percent", mem)

        bat = self.linux.get_battery_status()
        self.assertIn("status", bat)

        disk = self.linux.get_disk_usage()
        self.assertIn("free_gb", disk)

        vitals = self.linux.get_system_vitals()
        self.assertIn("cpu_percent", vitals)
        self.assertIn("ram_percent", vitals)
        self.assertIn("disk_free_gb", vitals)

    def test_clipboard_fallback(self):
        ok = self.linux.set_text("test_linux_clip")
        self.assertTrue(ok)
        self.assertEqual(self.linux.get_text(), "test_linux_clip")

    def test_notifications_and_input(self):
        self.linux.post_notification("Linux", "Notify test")
        self.linux.show_notification("Linux", "Notify test")
        self.linux.type_text("ls -la")
        self.linux.send_hotkey("ctrl", "alt", "t")
        self.linux.press_key("Return")

    def test_screen_capture(self):
        data = self.linux.capture_screen()
        self.assertIsNotNone(data)
        self.assertTrue(data.startswith(b"\x89PNG"))


class TestWindowsHAL(unittest.TestCase):
    """Verifies WindowsHAL native Win32/WinRT interactions and ctypes fallbacks."""

    def setUp(self):
        self.win = WindowsHAL()

    def test_platform_identifier(self):
        self.assertEqual(self.win.platform_name, "windows")

    def test_active_window_and_listing(self):
        win = self.win.get_active_window()
        self.assertIsInstance(win, dict)
        self.assertIn("title", win)
        self.assertIn("class_name", win)
        self.assertIn("pid", win)
        self.assertIn("rect", win)

        title = self.win.get_active_window_title()
        self.assertIsInstance(title, str)

        cls_name = self.win.get_active_window_class()
        self.assertIsInstance(cls_name, str)

        windows = self.win.list_windows()
        self.assertIsInstance(windows, list)
        self.assertGreater(len(windows), 0)

    def test_window_operations(self):
        # Safe execution even when no window handles are matching
        self.assertIsInstance(self.win.focus_window("NonexistentWindowTargetXYZ"), bool)
        self.assertIsInstance(self.win.minimize_window(0), bool)
        self.assertIsInstance(self.win.maximize_window(0), bool)
        self.assertIsInstance(self.win.snap_window("left"), bool)

    def test_vitals_telemetry(self):
        cpu = self.win.get_cpu_usage()
        self.assertIsInstance(cpu, float)

        mem = self.win.get_memory_usage()
        self.assertIn("total_gb", mem)
        self.assertIn("percent", mem)
        self.assertGreater(mem["total_gb"], 0)

        bat = self.win.get_battery_status()
        self.assertIn("status", bat)

        disk = self.win.get_disk_usage()
        self.assertIn("total_gb", disk)
        self.assertIn("free_gb", disk)
        self.assertGreater(disk["total_gb"], 0)

        vitals = self.win.get_system_vitals()
        self.assertIn("cpu_percent", vitals)
        self.assertIn("ram_percent", vitals)
        self.assertIn("ram_pct", vitals)
        self.assertIn("disk_free_gb", vitals)
        self.assertIn("active_window", vitals)

    def test_clipboard_operations(self):
        with patch("pyperclip.copy") as mock_copy, patch("pyperclip.paste", return_value="win_clip"):
            self.assertTrue(self.win.set_text("win_clip"))
            mock_copy.assert_called_with("win_clip")
            self.assertEqual(self.win.get_text(), "win_clip")
            self.assertEqual(self.win.get_clipboard_text(), "win_clip")

    def test_biometrics_delegation(self):
        with patch("windows_hello.WindowsHello.is_available", return_value=True), \
             patch("windows_hello.WindowsHello.verify_sync", return_value=True):
            self.assertTrue(self.win.is_available())
            self.assertTrue(self.win.authenticate("Consequential action"))

        with patch("windows_hello.WindowsHello.is_available", return_value=False), \
             patch("windows_hello.WindowsHello.verify_sync", return_value=False):
            self.assertFalse(self.win.is_available())
            self.assertFalse(self.win.authenticate("Consequential action"))

    def test_input_simulation(self):
        with patch("pyautogui.write") as mock_write, \
             patch("pyautogui.hotkey") as mock_hotkey, \
             patch("pyautogui.press") as mock_press:
            self.assertTrue(self.win.type_text("helm run"))
            mock_write.assert_called_once_with("helm run")

            self.assertTrue(self.win.send_hotkey("ctrl", "v"))
            mock_hotkey.assert_called_once_with("ctrl", "v")

            self.assertTrue(self.win.press_key("tab"))
            mock_press.assert_called_once_with("tab")


class TestCrossPlatformDecoupling(unittest.TestCase):
    """Ensures non-Windows HALs and core interfaces operate completely decoupled from Win32."""

    def test_mock_hal_isolated_from_os(self):
        """MockHAL must work in a pure headless sandbox with zero platform APIs."""
        mock = MockHAL()
        self.assertEqual(mock.platform_name, "mock")
        mock.post_notification("Test", "Isolated notification")
        mock.type_text("test input")
        mock.send_hotkey("ctrl", "c")
        self.assertTrue(mock.authenticate("Test reason"))
        vitals = mock.get_system_vitals()
        self.assertIn("cpu_percent", vitals)

    def test_all_classes_exported_in_module_all(self):
        """Important HAL symbols are accessible directly from helm_hal."""
        for symbol in (
            "IWindowManager",
            "INotificationManager",
            "IBiometrics",
            "ISystemVitals",
            "IClipboardManager",
            "IInputSimulator",
            "BaseHAL",
            "WindowsHAL",
            "DarwinHAL",
            "MacOSHAL",
            "LinuxHAL",
            "MockHAL",
            "get_hal",
            "set_hal",
            "reset_hal",
        ):
            self.assertTrue(hasattr(helm_hal, symbol), f"helm_hal is missing symbol: {symbol}")


if __name__ == "__main__":
    unittest.main()
