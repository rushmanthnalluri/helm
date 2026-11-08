"""Unit Tests for Batch 5 Capabilities:
- Quick Notes & Scratchpad with Instant Pin/Copy (quick_notes.py)
- Workspace Presets & Multi-Window Layout Manager (workspace_manager.py)
- System Tray Quick Menu & Unified HUD (tray_hud.py)
- Fast-Path Voice & Remote Integrations
"""
import os
import tempfile
import unittest
import quick_notes
import workspace_manager
import tray_hud
import homie

class TestBatch5Features(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_batch5.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_quick_notes_crud_and_pinning(self):
        # 1. Save notes
        id1 = quick_notes.save_quick_note("Remember to deploy update", is_pinned=False, db_path=self.db_path)
        id2 = quick_notes.save_quick_note("Critical API key", is_pinned=True, db_path=self.db_path)
        id3 = quick_notes.save_quick_note("Review PR #42", is_pinned=False, db_path=self.db_path)

        self.assertGreater(id1, 0)
        self.assertGreater(id2, 0)
        self.assertGreater(id3, 0)

        # 2. Query recent notes: pinned should be first regardless of timestamp
        notes = quick_notes.get_recent_notes(limit=10, db_path=self.db_path)
        self.assertEqual(len(notes), 3)
        self.assertEqual(notes[0]['id'], id2) # id2 was saved with is_pinned=True
        self.assertEqual(notes[0]['is_pinned'], 1)

        # 3. Toggle pin on id1
        new_state = quick_notes.toggle_pin(id1, db_path=self.db_path)
        self.assertTrue(new_state)

        pinned = quick_notes.get_pinned_notes(limit=10, db_path=self.db_path)
        self.assertEqual(len(pinned), 2)
        pinned_ids = [p['id'] for p in pinned]
        self.assertIn(id1, pinned_ids)
        self.assertIn(id2, pinned_ids)

        # 4. Toggle pin off
        new_state_off = quick_notes.toggle_pin(id1, db_path=self.db_path)
        self.assertFalse(new_state_off)

        # 5. Delete note
        ok = quick_notes.delete_note(id3, db_path=self.db_path)
        self.assertTrue(ok)
        notes_after = quick_notes.get_recent_notes(limit=10, db_path=self.db_path)
        self.assertEqual(len(notes_after), 2)

    def test_workspace_manager_save_and_restore(self):
        mock_windows = [
            {
                'proc_name': 'Code.exe',
                'title': 'main.py - Visual Studio Code',
                'rect': [0, 0, 800, 900]
            },
            {
                'proc_name': 'chrome.exe',
                'title': 'GitHub - Antigravity',
                'rect': [800, 0, 1600, 900]
            },
            {
                'proc_name': 'TextInputHost.exe', # Should be filtered out
                'title': 'Windows Input Experience',
                'rect': [0, 0, 100, 100]
            }
        ]

        # 1. Save preset 'dev'
        ok, msg, count = workspace_manager.save_workspace_preset("dev", windows_list=mock_windows, db_path=self.db_path)
        self.assertTrue(ok)
        self.assertEqual(count, 2)
        self.assertIn("dev", msg)

        # 2. List presets
        presets = workspace_manager.get_all_presets(db_path=self.db_path)
        self.assertEqual(presets, ["dev"])

        # 3. Restore preset where chrome is running but Code.exe is missing
        current_running = [
            {
                'hwnd': 12345,
                'proc_name': 'chrome.exe',
                'title': 'New Tab - Google Chrome',
                'rect': [100, 100, 500, 500]
            }
        ]
        ok_rest, msg_rest, details = workspace_manager.restore_workspace_preset(
            "dev", current_windows_list=current_running, db_path=self.db_path
        )
        self.assertTrue(ok_rest)
        self.assertEqual(details['restored'], 1)
        self.assertEqual(details['total'], 2)
        self.assertEqual(details['missing'], ['Code.exe'])

        # 4. Restore preset where both are running
        current_both = [
            {'hwnd': 111, 'proc_name': 'code.exe', 'title': 'Code', 'rect': [0, 0, 100, 100]},
            {'hwnd': 222, 'proc_name': 'chrome.exe', 'title': 'Chrome', 'rect': [0, 0, 100, 100]}
        ]
        ok_both, msg_both, details_both = workspace_manager.restore_workspace_preset(
            "dev", current_windows_list=current_both, db_path=self.db_path
        )
        self.assertTrue(ok_both)
        self.assertEqual(details_both['restored'], 2)
        self.assertEqual(details_both['total'], 2)
        self.assertEqual(len(details_both['missing']), 0)

        # 5. Delete preset
        ok_del = workspace_manager.delete_preset("dev", db_path=self.db_path)
        self.assertTrue(ok_del)
        self.assertEqual(len(workspace_manager.get_all_presets(db_path=self.db_path)), 0)

    def test_tray_hud_helpers(self):
        # 1. Truncate for menu
        self.assertEqual(tray_hud.truncate_for_menu("Short note"), "Short note")
        long_txt = "This is a very long note that exceeds the thirty character maximum width"
        truncated = tray_hud.truncate_for_menu(long_txt, max_length=25)
        self.assertTrue(len(truncated) <= 25)
        self.assertTrue(truncated.endswith("..."))

        # 2. Default icon generation
        img = tray_hud.create_default_icon_image()
        self.assertEqual(img.size, (64, 64))

    def test_fast_commands_batch5(self):
        # 1. Take note
        handled, msg = homie.try_fast_command("take note buy groceries for dinner")
        self.assertTrue(handled)
        self.assertIn("Saved note", msg)
        self.assertIn("buy groceries", msg)

        # 2. Show notes
        handled2, msg2 = homie.try_fast_command("show notes")
        self.assertTrue(handled2)
        self.assertIn("Scratchpad Notes", msg2)

if __name__ == '__main__':
    unittest.main()
