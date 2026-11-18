"""Unit tests for Omnibar Start Menu & Windows Indexer with RapidFuzz Search."""

import os
import unittest
from unittest.mock import MagicMock, patch

import homie_omnibar
from homie_omnibar import (
    DEFAULT_ACTIONS,
    OmnibarController,
    OmnibarIndexer,
    index_running_windows,
    index_start_menu,
    launch_result,
    search_index,
)


class TestOmnibarIndexer(unittest.TestCase):
    def setUp(self):
        self.indexer = OmnibarIndexer()

    def test_start_menu_indexer_returns_list_of_dicts(self):
        """Verify index_start_menu returns a list of {name, path, icon} items."""
        apps = self.indexer.index_start_menu()
        self.assertIsInstance(apps, list)
        if apps:
            first = apps[0]
            self.assertIn("name", first)
            self.assertIn("path", first)
            self.assertIn("icon", first)
            self.assertTrue(len(first["name"]) > 0)
            self.assertTrue(len(first["path"]) > 0)

    def test_start_menu_caching_behavior(self):
        """Verify repeated calls return cached items without full re-walk."""
        with patch("os.walk") as mock_walk:
            mock_walk.return_value = [("C:\\Dummy", [], ["test.lnk"])]
            with patch("win32com.client.Dispatch") as mock_dispatch:
                mock_shell = MagicMock()
                mock_sc = MagicMock()
                mock_sc.TargetPath = "C:\\Dummy\\test.exe"
                mock_shell.CreateShortcut.return_value = mock_sc
                mock_dispatch.return_value = mock_shell

                indexer = OmnibarIndexer()
                first_run = indexer.index_start_menu(force=True)
                self.assertEqual(len(first_run), 1)
                self.assertEqual(first_run[0]["name"], "test")
                self.assertEqual(first_run[0]["path"], "C:\\Dummy\\test.exe")

                # Second run should use cached results without calling walk
                mock_walk.reset_mock()
                second_run = indexer.index_start_menu(force=False)
                mock_walk.assert_not_called()
                self.assertEqual(second_run, first_run)

    def test_running_windows_indexer(self):
        """Verify index_running_windows enumerates visible windows with titles and PIDs."""
        with patch("win32gui.EnumWindows") as mock_enum, \
             patch("win32gui.IsWindowVisible", return_value=True), \
             patch("win32gui.GetWindowText", return_value="Test - Notepad"), \
             patch("win32process.GetWindowThreadProcessId", return_value=(100, 1234)):

            def fake_enum(callback, extra):
                callback(9999, extra)

            mock_enum.side_effect = fake_enum

            indexer = OmnibarIndexer()
            windows = indexer.index_running_windows()

            self.assertEqual(len(windows), 1)
            win = windows[0]
            self.assertEqual(win["name"], "Test - Notepad")
            self.assertEqual(win["hwnd"], 9999)
            self.assertEqual(win["pid"], 1234)
            self.assertEqual(win["type"], "window")

    def test_search_index_empty_query_returns_default_actions(self):
        """Verify empty query falls back to DEFAULT_ACTIONS."""
        results = self.indexer.search_index("")
        self.assertEqual(len(results), len(DEFAULT_ACTIONS))
        self.assertEqual(results[0]["id"], DEFAULT_ACTIONS[0]["id"])

        results_spaces = self.indexer.search_index("   ")
        self.assertEqual(len(results_spaces), len(DEFAULT_ACTIONS))

    def test_search_index_fuzzy_matching_and_ranking(self):
        """Verify RapidFuzz WRatio sorts and ranks top 10 items."""
        indexer = OmnibarIndexer()
        # Seed custom mock apps
        indexer._cached_apps = [
            {"id": "app:code", "name": "Visual Studio Code", "path": "code.exe", "icon": "🚀", "type": "app"},
            {"id": "app:calc", "name": "Calculator", "path": "calc.exe", "icon": "🚀", "type": "app"},
            {"id": "app:brave", "name": "Brave Browser", "path": "brave.exe", "icon": "🚀", "type": "app"},
            {"id": "app:terminal", "name": "Windows Terminal", "path": "wt.exe", "icon": "🚀", "type": "app"},
            {"id": "app:notepad", "name": "Notepad", "path": "notepad.exe", "icon": "🚀", "type": "app"},
        ]
        indexer._last_index_time = 1e12  # far future to avoid reindexing

        with patch.object(indexer, "index_running_windows", return_value=[
            {"id": "win:555", "name": "Brave - GitHub", "title": "Brave - GitHub", "hwnd": 555, "pid": 4321, "type": "window", "icon": "🪟"}
        ]):
            results = indexer.search_index("brave")
            self.assertTrue(len(results) >= 2)
            # Both Brave open window and Brave application should be top results
            names = [r["name"] for r in results[:2]]
            self.assertTrue(any("Brave" in n for n in names))
            self.assertTrue(len(results) <= 10)

    def test_launch_result_app(self):
        """Verify launch_result invokes os.startfile for app items."""
        indexer = OmnibarIndexer()
        app_item = {"id": "app:notepad", "type": "app", "path": "notepad.exe", "name": "Notepad"}

        with patch("os.startfile") as mock_startfile:
            success = indexer.launch_result(app_item)
            self.assertTrue(success)
            mock_startfile.assert_called_once_with("notepad.exe")

    def test_launch_result_window(self):
        """Verify launch_result brings window to foreground."""
        indexer = OmnibarIndexer()
        win_item = {"id": "win:1234", "type": "window", "hwnd": 1234, "name": "Chrome"}

        with patch("win32gui.IsIconic", return_value=False), \
             patch("win32gui.ShowWindow") as mock_show, \
             patch("win32gui.SetForegroundWindow") as mock_set_fg:
            success = indexer.launch_result(win_item)
            self.assertTrue(success)
            mock_set_fg.assert_called_once_with(1234)

    def test_omnibar_controller_search_and_launch_api(self):
        """Verify OmnibarController and OmnibarApi integrate correctly."""
        ctrl = OmnibarController()
        ctrl.hide = MagicMock()

        # Test search
        res = ctrl.search_omnibar("calc")
        self.assertIsInstance(res, list)

        # Test launch action
        with patch.object(ctrl.indexer, "launch_result", return_value=True) as mock_launch:
            item = {"id": "app:calc", "type": "app", "path": "calc.exe"}
            ctrl.indexer._results_cache["app:calc"] = item
            ok = ctrl.launch_omnibar_result("app:calc")
            self.assertTrue(ok)
            ctrl.hide.assert_called_once()
            mock_launch.assert_called_once_with(item)

    def test_module_level_helpers(self):
        """Verify module-level functions exist and are callable."""
        self.assertTrue(callable(index_start_menu))
        self.assertTrue(callable(index_running_windows))
        self.assertTrue(callable(search_index))
        self.assertTrue(callable(launch_result))

        # Check search_index with empty string
        res = search_index("")
        self.assertEqual(len(res), len(DEFAULT_ACTIONS))


if __name__ == "__main__":
    unittest.main()
