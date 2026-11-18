"""test_dpi_aware.py - Tests for per-monitor DPI-aware coordinate mapping and hardware-level mouse clicks."""

from unittest.mock import MagicMock, patch
import pytest

from windows_tools import DPIAwareCoords, dpi_click, click_at


class TestDPIAwareCoords:
    def test_get_monitor_dpi_map_structure(self):
        """Verify monitor map returns expected keys and non-zero positive DPI / scale."""
        monitor_map = DPIAwareCoords.get_monitor_dpi_map(force_refresh=True)
        assert isinstance(monitor_map, list)
        assert len(monitor_map) >= 1

        for mon in monitor_map:
            assert "rect" in mon
            assert len(mon["rect"]) == 4
            assert "dpi" in mon
            assert mon["dpi"] > 0
            assert "scale" in mon
            assert mon["scale"] > 0.0
            # Scale should be dpi / 96
            assert pytest.approx(mon["scale"], 0.01) == mon["dpi"] / 96.0

    def test_caching_and_display_change(self):
        """Verify map caching and invalidation on handle_display_change."""
        map1 = DPIAwareCoords.get_monitor_dpi_map(force_refresh=True)
        map2 = DPIAwareCoords.get_monitor_dpi_map()
        assert map1 is map2

        DPIAwareCoords.handle_display_change()
        assert DPIAwareCoords._cached_map is None

    def test_logical_and_physical_conversion_multi_monitor(self):
        """Test logical <-> physical coordinate conversions across mixed-DPI monitors."""
        mock_monitors = [
            # Monitor 1: 1080p @ 100% DPI (96 dpi, scale = 1.0)
            {
                "rect": (0, 0, 1920, 1080),
                "dpi": 96,
                "scale": 1.0,
                "handle": 1,
            },
            # Monitor 2: 4K @ 150% DPI (144 dpi, scale = 1.5), placed to the right
            {
                "rect": (1920, 0, 5760, 2160),
                "dpi": 144,
                "scale": 1.5,
                "handle": 2,
            },
        ]

        with patch.object(DPIAwareCoords, "get_monitor_dpi_map", return_value=mock_monitors):
            # Point on Monitor 1
            phys_x1, phys_y1 = DPIAwareCoords.logical_to_physical(100, 200)
            assert phys_x1 == 100
            assert phys_y1 == 200
            log_x1, log_y1 = DPIAwareCoords.physical_to_logical(phys_x1, phys_y1)
            assert log_x1 == 100
            assert log_y1 == 200

            # Point on Monitor 2 (4K at 150% scale, offset at x=1920)
            # Logical x = 2000 -> relative to monitor 2 origin is 80 -> physical 80 * 1.5 = 120 -> physical x = 2040
            # Logical y = 400 -> relative to monitor 2 origin is 400 -> physical 400 * 1.5 = 600 -> physical y = 600
            phys_x2, phys_y2 = DPIAwareCoords.logical_to_physical(2000, 400)
            assert phys_x2 == 2040
            assert phys_y2 == 600

            # Reverse round-trip
            log_x2, log_y2 = DPIAwareCoords.physical_to_logical(2040, 600)
            assert log_x2 == 2000
            assert log_y2 == 400

    def test_point_outside_all_monitors_fallback(self):
        """Points outside all monitors should safely fall back to the first monitor."""
        mock_monitors = [
            {
                "rect": (0, 0, 1920, 1080),
                "dpi": 96,
                "scale": 1.0,
                "handle": 1,
            }
        ]
        with patch.object(DPIAwareCoords, "get_monitor_dpi_map", return_value=mock_monitors):
            phys_x, phys_y = DPIAwareCoords.logical_to_physical(-500, -500)
            assert phys_x == -500
            assert phys_y == -500


class TestDpiClick:
    @patch("ctypes.windll.user32.SendInput", return_value=3)
    @patch("win32api.GetSystemMetrics")
    def test_dpi_click_dispatches_sendinput(self, mock_metrics, mock_send_input):
        """Verify dpi_click converts coordinates and calls SendInput with 3 events."""
        # Virtual desktop: 0, 0, 3840, 2160
        mock_metrics.side_effect = lambda metric: {
            76: 0,     # SM_XVIRTUALSCREEN
            77: 0,     # SM_YVIRTUALSCREEN
            78: 3840,  # SM_CXVIRTUALSCREEN
            79: 2160,  # SM_CYVIRTUALSCREEN
        }.get(metric, 1920)

        mock_monitors = [
            {"rect": (0, 0, 3840, 2160), "dpi": 96, "scale": 1.0, "handle": 1}
        ]

        with patch.object(DPIAwareCoords, "get_monitor_dpi_map", return_value=mock_monitors):
            res = dpi_click(1920, 1080, button="left")
            assert res is True
            assert mock_send_input.called
            # First arg to SendInput is event count (3)
            assert mock_send_input.call_args[0][0] == 3

    @patch("ctypes.windll.user32.SendInput", side_effect=RuntimeError("Hardware locked"))
    @patch("pyautogui.click")
    def test_dpi_click_fallback_to_pyautogui(self, mock_pyautogui_click, mock_send_input):
        """Verify dpi_click falls back to pyautogui.click if hardware SendInput fails."""
        res = dpi_click(250, 350, button="right")
        assert res is True
        mock_pyautogui_click.assert_called_once_with(250, 350, button="right")

    def test_click_at_alias(self):
        """Verify click_at calls dpi_click."""
        with patch("windows_tools.dpi_click", return_value=True) as mock_dpi_click:
            res = click_at(100, 200, button="middle")
            assert res is True
            mock_dpi_click.assert_called_once_with(100, 200, button="middle")
