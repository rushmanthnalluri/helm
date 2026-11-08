"""Unit Tests for Batch 3 Capabilities:
- Shared Event Log (event_log.py)
- Presence & Idle Catch-Up Monitor (presence_monitor.py)
- Local File Search Indexer (file_indexer.py)
- Contextual Action Pill (action_pill.py)
- Windows Notification Mirror (notification_mirror.py)
"""
import os
import time
import tempfile
import unittest
import event_log
import presence_monitor
import file_indexer
import action_pill
import notification_mirror
from clipboard_classifier import ClipboardClassification

class TestBatch3Features(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_homie.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_event_log_crud(self):
        # 1. Log events
        t0 = time.time()
        rowid1 = event_log.log_event("notification", "Test toast from Outlook", occurred_at=t0 - 10, db_path=self.db_path)
        rowid2 = event_log.log_event("vitals", "RAM high alert: 93%", occurred_at=t0 - 5, db_path=self.db_path)
        self.assertGreater(rowid1, 0)
        self.assertGreater(rowid2, rowid1)

        # 2. Query since timestamp
        events = event_log.get_events_since(t0 - 15, limit=10, db_path=self.db_path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['event_type'], 'notification')
        self.assertEqual(events[1]['event_type'], 'vitals')

        # 3. Query recent
        recent = event_log.get_recent_events(limit=1, db_path=self.db_path)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]['event_type'], 'vitals')

    def test_presence_monitor_state_transitions(self):
        returned_calls = []

        def on_returned(away_dur, events):
            returned_calls.append((away_dur, events))

        monitor = presence_monitor.PresenceMonitor(
            away_threshold_seconds=100.0,
            on_user_returned_callback=on_returned,
            db_path=self.db_path
        )

        # 1. Active state (idle = 10s)
        fired = monitor.check_presence(idle_seconds=10.0)
        self.assertFalse(fired)
        self.assertFalse(monitor.is_currently_away)

        # 2. Stepped away (idle = 150s >= 100s threshold)
        fired = monitor.check_presence(idle_seconds=150.0)
        self.assertFalse(fired)
        self.assertTrue(monitor.is_currently_away)
        self.assertIsNotNone(monitor.away_started_at)

        # Log an event that happens during absence
        event_log.log_event("notification", "WhatsApp: Message from Sarah", db_path=self.db_path)

        # 3. User returns (idle = 0.5s < 3.0s)
        fired = monitor.check_presence(idle_seconds=0.5)
        self.assertTrue(fired)
        self.assertFalse(monitor.is_currently_away)
        self.assertEqual(len(returned_calls), 1)
        away_duration, missed = returned_calls[0]
        self.assertGreater(away_duration, 0)
        self.assertGreaterEqual(len(missed), 1)
        self.assertEqual(missed[0]['event_type'], 'notification')

    def test_file_indexer_scan_and_search(self):
        # Create test directory structure with files
        scan_dir = os.path.join(self.temp_dir.name, "indexed_files")
        os.makedirs(scan_dir, exist_ok=True)
        sub_dir = os.path.join(scan_dir, "projects")
        os.makedirs(sub_dir, exist_ok=True)

        f1 = os.path.join(scan_dir, "Quarterly_Report_2026.pdf")
        with open(f1, "w") as f:
            f.write("test report content")

        f2 = os.path.join(sub_dir, "resume_rushmanth.docx")
        with open(f2, "w") as f:
            f.write("resume content")

        # Build index
        count = file_indexer.build_file_index(roots=[scan_dir], db_path=self.db_path)
        self.assertEqual(count, 2)

        # Search for 'report'
        matches = file_indexer.search_files("report", limit=5, db_path=self.db_path)
        self.assertEqual(len(matches), 1)
        self.assertIn("Quarterly_Report_2026.pdf", matches[0]['file_name'])

        # Search for 'resume'
        matches_res = file_indexer.search_files("resume", limit=5, db_path=self.db_path)
        self.assertEqual(len(matches_res), 1)
        self.assertEqual(matches_res[0]['file_name'], "resume_rushmanth.docx")

        # Get by ID
        rec = file_indexer.get_file_by_id(matches_res[0]['id'], db_path=self.db_path)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['file_path'], f2)

        # Test format_file_size
        self.assertEqual(file_indexer.format_file_size(500), "500 B")
        self.assertEqual(file_indexer.format_file_size(2048), "2.0 KB")
        self.assertEqual(file_indexer.format_file_size(10485760), "10.0 MB")

    def test_action_pill_mapping_and_actions(self):
        # 1. Action map resolution
        err_cls = ClipboardClassification("error", True, "explain_error", "Error")
        acts = action_pill.get_actions_for_classification(err_cls)
        self.assertTrue(any(a['id'] == 'explain_error' for a in acts))

        url_cls = ClipboardClassification("url", True, "open_url", "URL")
        acts_url = action_pill.get_actions_for_classification(url_cls)
        self.assertTrue(any(a['id'] == 'open_url' for a in acts_url))

        # 2. format_json action
        raw_json = '{"name":"Homie","status":"online"}'
        ok, msg = action_pill.execute_action('format_json', raw_json)
        self.assertTrue(ok)
        import pyperclip
        self.assertIn('\n  "name": "Homie"', pyperclip.paste())

        # 3. copy_clean_url action
        dirty_url = "https://example.com/article?id=42&utm_source=twitter&utm_medium=social"
        ok, msg = action_pill.execute_action('copy_clean_url', dirty_url)
        self.assertTrue(ok)
        self.assertEqual(pyperclip.paste(), "https://example.com/article?id=42")

        # 4. word_count action
        sample = "The quick brown fox jumps over the lazy dog."
        ok, msg = action_pill.execute_action('word_count', sample)
        self.assertTrue(ok)
        self.assertIn("9 words", msg)

    def test_notification_mirror_initialization(self):
        mirror = notification_mirror.NotificationMirror(db_path=self.db_path)
        self.assertTrue(mirror.is_supported())
        self.assertEqual(mirror.last_seen_id, 0)
        self.assertFalse(mirror.keep_running)

if __name__ == '__main__':
    unittest.main()
