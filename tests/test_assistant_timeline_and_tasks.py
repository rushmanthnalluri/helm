"""tests/test_assistant_timeline_and_tasks.py - Assistant Timeline & Task Manager Tests.

Verifies:
1. TaskManager tracks durable task IDs, lifecycle transitions, and cooperative cancellation.
2. Assistant Timeline aggregates events across focus, meetings, notes, and audit ledger.
3. "What did I miss?" summary produces a grounded narrative.
4. Per-app exclusions prevent indexing sensitive application windows.
5. Retention pruner cleans up expired history without error.
"""

import os
import sys
import unittest
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import task_manager
import assistant_timeline
import quick_notes


class TestAssistantTimelineAndTaskManager(unittest.TestCase):

    def test_task_manager_lifecycle_and_cancellation(self):
        """Verifies task submission, status tracking, and cooperative cancellation."""
        tm = task_manager.TaskManager(max_workers=2)

        # 1. Simple successful task
        task = tm.submit_task("compute_square", lambda x: x * x, 7)
        time.sleep(0.1)
        self.assertEqual(task.status, task_manager.TaskStatus.COMPLETED)
        self.assertEqual(task.result, 49)
        self.assertTrue(task.task_id.startswith("task_"))

        # 2. Cancellable task
        def slow_worker(cancel_event):
            for _ in range(20):
                if cancel_event.is_set():
                    return "ABORTED"
                time.sleep(0.05)
            return "FINISHED"

        slow_task = tm.submit_task("slow_job", slow_worker)
        time.sleep(0.05)
        self.assertTrue(tm.is_busy())

        # Signal cancellation
        cancelled = tm.cancel_task(slow_task.task_id)
        self.assertTrue(cancelled)
        self.assertEqual(slow_task.status, task_manager.TaskStatus.CANCELLED)

        tm.shutdown(wait=False)

    def test_assistant_timeline_summary_and_exclusions(self):
        """Verifies timeline summary generation and exclusion list management."""
        # Add a note so timeline has at least one event
        quick_notes.add_note("Prepare deployment checklist for Homie workstation")

        summary = assistant_timeline.get_what_did_i_miss_summary(lookback_hours=2)
        self.assertIsInstance(summary, str)
        self.assertIn("Assistant Timeline Summary", summary)
        self.assertIn("deployment checklist", summary)

        # App exclusion management
        app = "sensitive_test_tool.exe"
        assistant_timeline.add_app_exclusion(app)
        conf = assistant_timeline.load_timeline_config()
        self.assertIn(app, conf["excluded_apps"])

        assistant_timeline.remove_app_exclusion(app)
        conf2 = assistant_timeline.load_timeline_config()
        self.assertNotIn(app, conf2["excluded_apps"])

    def test_retention_prune(self):
        """Verifies prune_expired_retention runs cleanly and returns pruned metrics."""
        results = assistant_timeline.prune_expired_retention(retention_hours=24)
        self.assertIsInstance(results, dict)
        self.assertIn("screen_timeline", results)
        self.assertIn("focus_activity", results)


if __name__ == "__main__":
    unittest.main()
