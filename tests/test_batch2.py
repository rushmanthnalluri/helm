import os
import tempfile
import unittest
import clipboard_classifier
import reminder_scheduler
import windows_tools
import voice

class TestBatch2Features(unittest.TestCase):
    def test_clipboard_classifier(self):
        # 1. Error traceback
        tb = """Traceback (most recent call last):
  File "app.py", line 12, in <module>
    raise ValueError("Invalid configuration")
ValueError: Invalid configuration"""
        res = clipboard_classifier.classify_clipboard_content(tb)
        self.assertEqual(res.content_type, 'error')
        self.assertTrue(res.action_available)

        # 2. URL
        url_text = "https://github.com/google-deepmind/antigravity"
        res = clipboard_classifier.classify_clipboard_content(url_text)
        self.assertEqual(res.content_type, 'url')
        self.assertTrue(res.action_available)

        # 3. JSON
        json_text = '{"status": "ok", "count": 42}'
        res = clipboard_classifier.classify_clipboard_content(json_text)
        self.assertEqual(res.content_type, 'json')

        # 4. Code
        code_text = "def calculate_sum(a: int, b: int) -> int:\n    return a + b"
        res = clipboard_classifier.classify_clipboard_content(code_text)
        self.assertEqual(res.content_type, 'code')

        # 5. Plain text
        plain = "Just a short message."
        res = clipboard_classifier.classify_clipboard_content(plain)
        self.assertEqual(res.content_type, 'plain_text')

    def test_reminder_scheduler_duration_parsing(self):
        self.assertEqual(reminder_scheduler.parse_duration_to_seconds("30s"), 30)
        self.assertEqual(reminder_scheduler.parse_duration_to_seconds("5m"), 300)
        self.assertEqual(reminder_scheduler.parse_duration_to_seconds("2h"), 7200)
        self.assertEqual(reminder_scheduler.parse_duration_to_seconds("1d"), 86400)
        with self.assertRaises(ValueError):
            reminder_scheduler.parse_duration_to_seconds("invalid_time")

    def test_reminder_scheduler_crud(self):
        # Use isolated temp file for reminders
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            old_file = reminder_scheduler.REMINDERS_FILE
            reminder_scheduler.REMINDERS_FILE = temp_path

            # Add reminder due in 1 second
            item = reminder_scheduler.add_reminder(chat_id="12345", duration_spec="1s", message_text="Test alert")
            self.assertIsNotNone(item)
            self.assertEqual(item['chat_id'], "12345")
            self.assertEqual(item['message'], "Test alert")

            # List active reminders
            active = reminder_scheduler.list_active_reminders("12345")
            self.assertEqual(len(active), 1)

            # Wait slightly for due
            import time
            time.sleep(1.2)
            due = reminder_scheduler.get_due_reminders()
            self.assertTrue(len(due) >= 1)

            # Mark fired
            reminder_scheduler.mark_reminder_fired(item['id'])
            active_after = reminder_scheduler.list_active_reminders("12345")
            self.assertEqual(len(active_after), 0)
        finally:
            reminder_scheduler.REMINDERS_FILE = old_file
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def test_windows_tools_top_processes(self):
        procs = windows_tools.get_top_processes(sort_by='memory', limit=5)
        self.assertTrue(isinstance(procs, list))
        self.assertGreater(len(procs), 0)
        first = procs[0]
        self.assertIn('pid', first)
        self.assertIn('name', first)
        self.assertIn('mem_mb', first)
        self.assertIn('mem_pct', first)
        self.assertIn('cpu_pct', first)

    def test_windows_tools_protected_kill(self):
        import psutil
        # Find actual PID of explorer or winlogon if running
        protected_pid = None
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if p.name().lower() in windows_tools.PROTECTED_PROCESS_NAMES:
                    protected_pid = p.pid
                    break
            except Exception:
                continue

        if protected_pid:
            ok, msg = windows_tools.kill_process_by_pid(protected_pid)
            self.assertFalse(ok)
            self.assertTrue("blocked" in msg.lower() or "critical" in msg.lower())

    def test_windows_tools_idle_seconds(self):
        idle = windows_tools.get_idle_seconds()
        self.assertGreaterEqual(idle, 0.0)

    def test_voice_tts_synthesis(self):
        tmp_wav = os.path.join(tempfile.gettempdir(), f"helm_test_tts_{os.getpid()}.wav")
        try:
            out_path = voice.synthesize_speech_to_wav("Testing Helm offline speech synthesis.", tmp_wav)
            self.assertEqual(out_path, tmp_wav)
            self.assertTrue(os.path.exists(tmp_wav))
            size = os.path.getsize(tmp_wav)
            self.assertGreater(size, 1000, f"Generated WAV too small ({size} bytes)")
        finally:
            if os.path.exists(tmp_wav):
                try:
                    os.remove(tmp_wav)
                except Exception:
                    pass

if __name__ == '__main__':
    unittest.main()
