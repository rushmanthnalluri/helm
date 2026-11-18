"""Unit tests for event-driven hotkey architecture using Win32 RegisterHotKey and GetMessageW pump."""
import unittest
from unittest.mock import MagicMock, patch
import time
import app


class TestHotkeyEventPump(unittest.TestCase):
    def setUp(self):
        self.homie_app = app.HomieApp.__new__(app.HomieApp)
        self.homie_app.omnibar = None
        self.homie_app.canvas = None
        self.homie_app.is_recording = False
        self.homie_app._running_hotkey = True
        self.homie_app._registered_hotkeys = set()
        self.homie_app._last_voice_release_time = 0.0
        self.homie_app._physical_ctrl_down = False
        self.homie_app._physical_alt_down = False
        self.homie_app._ll_hook = None
        self.homie_app._hotkey_thread_id = None
        self.homie_app._hotkey_thread = None

    def test_hotkey_interface_methods_exist(self):
        """Verify all hotkey interface methods exist on HomieApp."""
        expected_methods = [
            "_toggle_omnibar",
            "_toggle_canvas",
            "toggle_canvas",
            "_trigger_quick_note",
            "_handle_voice_press",
            "_watch_voice_release",
            "_dispatch_hotkey",
            "start_hotkey_listener",
            "stop_hotkey_listener",
            "handle_keyboard_event",
            "reset_physical_modifiers",
        ]
        for meth in expected_methods:
            self.assertTrue(hasattr(self.homie_app, meth), f"Missing method {meth}")
            self.assertTrue(callable(getattr(self.homie_app, meth)), f"{meth} is not callable")

    def test_dispatch_hotkey_routes_to_handlers(self):
        """Verify WM_HOTKEY IDs correctly route to their designated handlers."""
        self.homie_app._toggle_omnibar = MagicMock()
        self.homie_app._toggle_canvas = MagicMock()
        self.homie_app._trigger_quick_note = MagicMock()
        self.homie_app._handle_voice_press = MagicMock()

        # ID 1: Omnibar (Alt+Space)
        self.homie_app._dispatch_hotkey(1)
        self.homie_app._toggle_omnibar.assert_called_once()

        # ID 2: Canvas (Alt+C)
        self.homie_app._dispatch_hotkey(2)
        self.homie_app._toggle_canvas.assert_called_once()

        # ID 3: Quick Note (Ctrl+Alt+N)
        self.homie_app._dispatch_hotkey(3)
        self.homie_app._trigger_quick_note.assert_called_once()

        # ID 4 & 5: Voice hold-to-talk (Ctrl+Alt+Space & Ctrl+Shift+Space)
        self.homie_app._dispatch_hotkey(4)
        self.assertEqual(self.homie_app._handle_voice_press.call_count, 1)
        self.homie_app._dispatch_hotkey(5)
        self.assertEqual(self.homie_app._handle_voice_press.call_count, 2)

    def test_omnibar_cooldown_guard_after_voice_release(self):
        """Verify Alt+Space does not accidentally trigger Omnibar right after releasing voice hold."""
        self.homie_app._toggle_omnibar = MagicMock()
        self.homie_app._last_voice_release_time = time.time()  # Just released 0s ago

        # Should be suppressed by cooldown
        self.homie_app._dispatch_hotkey(1)
        self.homie_app._toggle_omnibar.assert_not_called()

        # Simulate voice release happened > 0.3s ago
        self.homie_app._last_voice_release_time = time.time() - 0.5
        self.homie_app._dispatch_hotkey(1)
        self.homie_app._toggle_omnibar.assert_called_once()

    def test_omnibar_suppressed_while_recording(self):
        """Verify Omnibar is not toggled while voice recording is actively in progress."""
        self.homie_app._toggle_omnibar = MagicMock()
        self.homie_app.is_recording = True
        self.homie_app._last_voice_release_time = time.time() - 10.0

        self.homie_app._dispatch_hotkey(1)
        self.homie_app._toggle_omnibar.assert_not_called()

    def test_canvas_toggle_dispatch(self):
        """Verify Canvas toggle forwards to canvas controller if available."""
        mock_canvas = MagicMock()
        self.homie_app.canvas = mock_canvas

        self.homie_app.toggle_canvas()
        mock_canvas.toggle.assert_called_once()

    def test_voice_press_initiates_recording(self):
        """Verify _handle_voice_press triggers start_listening and watchdog."""
        self.homie_app.start_listening = MagicMock()
        with patch("threading.Thread") as mock_thread:
            self.homie_app._handle_voice_press()
            self.homie_app.start_listening.assert_called_once()
            mock_thread.assert_called_once()

        # Subsequent call while already recording does nothing
        self.homie_app.is_recording = True
        self.homie_app.start_listening.reset_mock()
        self.homie_app._handle_voice_press()
        self.homie_app.start_listening.assert_not_called()

    def test_stop_hotkey_listener_cleanup(self):
        """Verify stop_hotkey_listener resets flags and attempts unregistration."""
        self.homie_app._registered_hotkeys = {1, 2, 3, 4, 5}
        self.homie_app._running_hotkey = True

        with patch("ctypes.windll.user32.UnregisterHotKey", return_value=1) as mock_unreg:
            self.homie_app.stop_hotkey_listener()
            self.assertFalse(self.homie_app._running_hotkey)
            self.assertEqual(len(self.homie_app._registered_hotkeys), 0)
            self.assertEqual(mock_unreg.call_count, 5)

    def test_win32_register_hotkey_live(self):
        """Live test of Win32 RegisterHotKey and UnregisterHotKey on the local platform."""
        import ctypes
        user32 = ctypes.windll.user32
        MOD_ALT = 0x0001
        MOD_NOREPEAT = 0x4000
        # Register a transient test hotkey ID 9999 (Alt + 0x58 = Alt + X)
        ok = user32.RegisterHotKey(None, 9999, MOD_ALT | MOD_NOREPEAT, 0x58)
        self.assertTrue(bool(ok), "Failed to register test hotkey via Win32 RegisterHotKey")
        unreg = user32.UnregisterHotKey(None, 9999)
        self.assertTrue(bool(unreg), "Failed to unregister test hotkey via Win32 UnregisterHotKey")


if __name__ == "__main__":
    unittest.main()
