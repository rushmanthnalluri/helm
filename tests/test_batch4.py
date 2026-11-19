"""Unit Tests for Batch 4 Capabilities:
- Active Window Time Tracking & Focus Snapshot (focus_tracker.py)
- Fullscreen & Meeting Auto-Suppression (focus_tracker.py)
- Meeting Intelligence & Notes System (meeting_notes.py)
- Fast-command & Productivity Integrations
"""
import os
import time
import tempfile
import unittest
import focus_tracker
import meeting_notes
import helm

class TestBatch4Features(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_batch4.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_focus_tracker_duration_formatting(self):
        self.assertEqual(focus_tracker.format_duration(0), "< 1m")
        self.assertEqual(focus_tracker.format_duration(45), "45s")
        self.assertEqual(focus_tracker.format_duration(120), "2m")
        self.assertEqual(focus_tracker.format_duration(3660), "1h 1m")
        self.assertEqual(focus_tracker.format_duration(7200), "2h 0m")

    def test_focus_tracker_recording_and_reports(self):
        t0 = time.time() - 3600

        # 1. Fleeting switch (< 2s) should be dropped
        res_noise = focus_tracker.record_focus_session("code.exe", "test.py", duration_seconds=1.2, occurred_at=t0, db_path=self.db_path)
        self.assertIsNone(res_noise)

        # 2. Legitimate focus sessions
        id1 = focus_tracker.record_focus_session("Code.exe", "main.py", duration_seconds=1800, occurred_at=t0 + 10, db_path=self.db_path)
        id2 = focus_tracker.record_focus_session("chrome.exe", "Claude AI", duration_seconds=1200, occurred_at=t0 + 1850, db_path=self.db_path)
        id3 = focus_tracker.record_focus_session("Code.exe", "test.py", duration_seconds=600, occurred_at=t0 + 3100, db_path=self.db_path)

        self.assertIsNotNone(id1)
        self.assertIsNotNone(id2)
        self.assertIsNotNone(id3)

        # 3. Aggregated focus report
        rep = focus_tracker.get_focus_report(lookback_hours=24, db_path=self.db_path)
        self.assertEqual(len(rep), 2)

        # Code.exe total = 1800 + 600 = 2400s (66.7%)
        self.assertEqual(rep[0]['application_name'], 'Code.exe')
        self.assertEqual(rep[0]['total_seconds'], 2400)
        self.assertEqual(rep[0]['formatted_duration'], '40m')
        self.assertAlmostEqual(rep[0]['percent'], 66.7, places=1)

        # chrome.exe total = 1200s (33.3%)
        self.assertEqual(rep[1]['application_name'], 'chrome.exe')
        self.assertEqual(rep[1]['total_seconds'], 1200)
        self.assertEqual(rep[1]['formatted_duration'], '20m')
        self.assertAlmostEqual(rep[1]['percent'], 33.3, places=1)

    def test_fullscreen_and_meeting_detection(self):
        # Basic functional check ensuring API returns a boolean without throwing
        is_busy = focus_tracker.is_foreground_window_fullscreen_or_meeting()
        self.assertIsInstance(is_busy, bool)

    def test_focus_tracker_state_transitions(self):
        tracker = focus_tracker.FocusTracker(poll_interval=0.1, db_path=self.db_path)
        self.assertFalse(tracker.keep_running)
        tracker.start()
        self.assertTrue(tracker.keep_running)
        time.sleep(0.3)
        tracker.stop()
        self.assertFalse(tracker.keep_running)

    def test_meeting_notes_crud_and_session(self):
        # 1. Manual save and query
        t0 = time.time() - 600
        mid = meeting_notes.save_meeting(
            title="Q4 Sprint Planning",
            started_at=t0,
            ended_at=t0 + 600,
            duration_seconds=600,
            transcript="Team discussed roadmap milestones.",
            summary="Key milestones committed for Q4.",
            db_path=self.db_path
        )
        self.assertGreater(mid, 0)

        recent = meeting_notes.list_recent_meetings(limit=5, db_path=self.db_path)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]['title'], "Q4 Sprint Planning")

        rec = meeting_notes.get_meeting_by_id(mid, db_path=self.db_path)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['title'], "Q4 Sprint Planning")

        # 2. Session state transitions
        sess = meeting_notes.MeetingSession(db_path=self.db_path)
        self.assertFalse(sess.is_active)

        # Start meeting
        ok, msg = sess.start_meeting("Architecture Review")
        self.assertTrue(ok)
        self.assertTrue(sess.is_active)
        self.assertEqual(sess.title, "Architecture Review")

        # Cannot double start
        ok2, msg2 = sess.start_meeting("Conflict Meeting")
        self.assertFalse(ok2)

        # Inject transcript segment
        sess.transcript_segments.append("Discussed distributed event stream architecture.")

        # Stop meeting
        ok_stop, data = sess.stop_meeting()
        self.assertTrue(ok_stop)
        self.assertFalse(sess.is_active)
        self.assertEqual(data['title'], "Architecture Review")
        self.assertIn("Architecture Review", data['summary'])

    def test_meeting_summary_generator(self):
        sess = meeting_notes.MeetingSession(db_path=self.db_path)
        # Empty transcript fallback
        summary_empty = sess._generate_summary("Empty Meeting", "", 120)
        self.assertIn("without detected spoken dialogue", summary_empty)

        # Non-empty transcript
        summary_text = sess._generate_summary("Design Sync", "Discussed login redesign and token expiration.", 300)
        self.assertTrue(len(summary_text) > 20)

    def test_fast_commands_integration(self):
        # 1. Focus report
        handled, msg = helm.try_fast_command("focus report")
        self.assertTrue(handled)
        self.assertIn("Focus Report", msg)

        # 2. Screen time
        handled, msg = helm.try_fast_command("what is my screen time")
        self.assertTrue(handled)
        self.assertIn("Focus Report", msg)

if __name__ == '__main__':
    unittest.main()
