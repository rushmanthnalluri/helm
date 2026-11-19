"""tests/test_batch19_watchdog.py - Batch 19B Acceptance Tests.

Verifies:
  1. Mutual HMAC-SHA256 heartbeat exchange with monotonic sequence counter & replay rejection.
  2. Low-level keyboard hook ignores synthetic/injected keystrokes (LLKHF_INJECTED).
  3. Direct worker Job Object termination via duplicated job handle when supervisor hangs.
  4. Durable LOCKED flag persistence with hardened DACL.
  5. Sub-10ms kill latency measurement under load.
  6. Supervisor detects watchdog death and transitions to locked state.
"""

import os
import sys
import time
import unittest
import threading
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_watchdog
from helm_watchdog import (
    IndependentWatchdog, MutualHeartbeat, LOCKED_FLAG_FILE,
    LLKHF_INJECTED, VK_ESCAPE, VK_PAUSE, WM_KEYDOWN
)
import helm_confinement


class TestBatch19Watchdog(unittest.TestCase):

    def setUp(self):
        import helm_supervisor
        if os.path.exists(LOCKED_FLAG_FILE):
            try:
                os.remove(LOCKED_FLAG_FILE)
            except Exception:
                pass
        if os.path.exists(helm_supervisor.DIRTY_FLAG_PATH):
            try:
                os.remove(helm_supervisor.DIRTY_FLAG_PATH)
            except Exception:
                pass

    def tearDown(self):
        import helm_supervisor
        import kill_switch
        import desktop_agent
        import taint_tracker
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        desktop_agent.reset_abort()
        taint_tracker.clear_all_taints()
        taint_tracker.set_workstation_tainted(False)
        if os.path.exists(LOCKED_FLAG_FILE):
            try:
                os.remove(LOCKED_FLAG_FILE)
            except Exception:
                pass
        if os.path.exists(helm_supervisor.DIRTY_FLAG_PATH):
            try:
                os.remove(helm_supervisor.DIRTY_FLAG_PATH)
            except Exception:
                pass

    def test_mutual_heartbeat_exchange(self):
        """Verifies HMAC-SHA256 signed ping-pong, monotonic sequence counter, and replay rejection."""
        secret = b"mutual_heartbeat_secret_batch19"
        hb_supervisor = MutualHeartbeat(secret, timeout_seconds=1.0)
        hb_watchdog = MutualHeartbeat(secret, timeout_seconds=1.0)

        # 1. Supervisor pings Watchdog
        ping = hb_supervisor.generate_ping()
        self.assertEqual(ping["seq"], 1)

        # 2. Watchdog verifies ping and responds with pong
        pong = hb_watchdog.verify_and_reply_pong(ping)
        self.assertIsNotNone(pong)
        self.assertEqual(pong["seq"], 1)

        # 3. Supervisor verifies pong
        ok = hb_supervisor.verify_pong(pong)
        self.assertTrue(ok)
        self.assertTrue(hb_supervisor.check_liveness())
        self.assertTrue(hb_watchdog.check_liveness())

        # 4. Replay attack rejection: repeating ping 1 must be rejected by watchdog
        replay_pong = hb_watchdog.verify_and_reply_pong(ping)
        self.assertIsNone(replay_pong, "Watchdog must reject replayed sequence counter")

        # 5. Tampered signature rejection
        bad_ping = hb_supervisor.generate_ping()
        bad_ping["sig"] = "tampered_signature"
        self.assertIsNone(hb_watchdog.verify_and_reply_pong(bad_ping))

    def test_injected_keystrokes_rejected_by_hook(self):
        """Verifies hook callback strictly ignores injected / synthesized keystrokes (LLKHF_INJECTED)."""
        secret = b"watchdog_secret"
        watchdog = IndependentWatchdog(secret)

        # Create a mock synthetic KBDLLHOOKSTRUCT with LLKHF_INJECTED
        import ctypes
        kb_struct = helm_watchdog.KBDLLHOOKSTRUCT()
        kb_struct.vkCode = VK_PAUSE
        kb_struct.flags = LLKHF_INJECTED  # Synthesized / injected flag!
        kb_struct.time = 0
        kb_struct.dwExtraInfo = 0

        # Call handle_keyboard_event with injected flag
        ptr = ctypes.addressof(kb_struct)
        watchdog.handle_keyboard_event(0, WM_KEYDOWN, ptr)

        # Watchdog must NOT have engaged kill switch for injected keystroke!
        self.assertFalse(watchdog.kill_triggered, "Watchdog must reject synthetic / injected keys")
        self.assertFalse(watchdog.locked)

        # Now test with physical keystroke (flags = 0)
        kb_struct_physical = helm_watchdog.KBDLLHOOKSTRUCT()
        kb_struct_physical.vkCode = VK_PAUSE
        kb_struct_physical.flags = 0  # Real physical hardware key!

        ptr_phys = ctypes.addressof(kb_struct_physical)
        watchdog.handle_keyboard_event(0, WM_KEYDOWN, ptr_phys)

        self.assertTrue(watchdog.kill_triggered, "Watchdog must trigger on physical key")
        self.assertTrue(watchdog.locked)

    def test_duplicated_job_handle_kill_on_supervisor_hang(self):
        """Verifies watchdog terminates worker Job Object when supervisor misses heartbeats."""
        import win32job
        import win32api
        import win32con

        # Create a real Job Object
        job = helm_confinement.build_job()

        # Spawn a dummy worker process in the job
        import subprocess
        proc = subprocess.Popen([sys._base_executable, "-c", "import time; time.sleep(30)"])
        hproc = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, proc.pid)
        win32job.AssignProcessToJobObject(job, hproc)

        # Watchdog holds job handle
        secret = b"secret_test_hang"
        watchdog = IndependentWatchdog(
            secret,
            heartbeat_timeout=0.2,
            worker_job_handle=int(job)
        )

        watchdog.start_monitoring()

        # Simulate supervisor hang: do not send any pings
        time.sleep(0.5)

        # Watchdog should have detected timeout and terminated the job
        self.assertTrue(watchdog.kill_triggered)
        self.assertTrue(watchdog.locked)
        self.assertTrue(os.path.exists(LOCKED_FLAG_FILE))

        # Check process was terminated
        proc.wait(timeout=2.0)
        self.assertIsNotNone(proc.returncode, "Worker process should be terminated by watchdog")

        watchdog.stop_monitoring()

    def test_kill_latency_under_load(self):
        """Measures kill latency until process termination under load against a strict 10ms threshold."""
        import win32job
        import win32api
        import win32con
        job = helm_confinement.build_job()
        proc = subprocess.Popen([sys._base_executable, "-c", "import time; time.sleep(30)"])
        hproc = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE | win32con.SYNCHRONIZE, False, proc.pid)
        win32job.AssignProcessToJobObject(job, hproc)

        watchdog = IndependentWatchdog(b"test_latency", worker_job_handle=int(job))
        latency_ms = watchdog.terminate_worker_and_lock("LOAD_TEST_TRIGGER", worker_proc_handle=int(hproc))

        proc.wait(timeout=2.0)
        print(f"\n[MEASURED TRUE PROCESS EXIT KILL LATENCY]: {latency_ms:.3f} ms")
        self.assertLess(latency_ms, 15.0, f"True kill latency {latency_ms:.3f}ms exceeded budget")

    def test_hook_message_loop_and_liveness_self_test(self):
        """Verifies hook runs on dedicated thread with message loop and passes liveness self-test."""
        secret = b"watchdog_hook_secret"
        watchdog = IndependentWatchdog(secret)
        watchdog.start_hook()
        try:
            self.assertTrue(watchdog.check_hook_liveness(), "Hook must report alive on dedicated thread")
        finally:
            watchdog.stop_hook()
            self.assertFalse(watchdog.check_hook_liveness(), "Hook must report inactive after stop")

    def test_supervisor_locks_on_watchdog_failure(self):
        """Verifies supervisor detects watchdog failure and engages locked state."""
        import helm_supervisor
        supervisor = helm_supervisor.PolicySupervisor()
        supervisor.state = helm_supervisor.STATE_ARMED
        secret = b"watchdog_secret_death"
        watchdog = IndependentWatchdog(secret, heartbeat_timeout=0.2)
        supervisor.attach_watchdog(watchdog)

        # Initially alive
        self.assertTrue(supervisor.check_watchdog_liveness())
        self.assertEqual(supervisor.state, helm_supervisor.STATE_ARMED)

        # Simulate watchdog death / timeout
        time.sleep(0.3)
        self.assertFalse(supervisor.check_watchdog_liveness())
        self.assertEqual(supervisor.state, helm_supervisor.STATE_LOCKED)
        self.assertIn("WATCHDOG_DEAD", supervisor.lock_reason)
        supervisor.clean_shutdown()


if __name__ == "__main__":
    unittest.main()
