"""Unit, integration, and security tests for Batch 18A:
Helm Worker Process Confinement, Job Object Sandboxing, and Supervisor LLM Proxy.
"""

import os
import sys
import time
import json
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_supervisor
from helm_supervisor import (
    PolicySupervisor, SupervisorClient, BinaryFrameCodec,
    MSG_PROXY_LLM, MSG_DATA, MSG_ERROR
)
import worker_confinement
from worker_confinement import (
    WorkerJobSandbox, SupervisorLLMProxy, PreInjectionTOCTOUGuard
)
import canary_monitor
import kill_switch
import taint_tracker
import shadow_mode


class TestBatch18Confinement(unittest.TestCase):

    def setUp(self):
        os.environ["HELM_TEST_ENV"] = "1"
        taint_tracker.clear_all_taints()
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        import desktop_agent
        desktop_agent.reset_abort()
        shadow_mode.set_shadow_mode(False)
        shadow_mode.clear_rate_limits()

    def tearDown(self):
        taint_tracker.clear_all_taints()
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        import desktop_agent
        desktop_agent.reset_abort()

    def test_windows_job_object_sandbox_configuration(self):
        """Verifies Windows Job Object sandbox initializes with KILL_ON_JOB_CLOSE and UI restrictions."""
        sandbox = WorkerJobSandbox()
        self.assertIsNotNone(sandbox.hjob, "Job Object handle should be valid on Windows")

        # Query Job Object information to verify limits
        import win32job
        info = win32job.QueryInformationJobObject(sandbox.hjob, win32job.JobObjectExtendedLimitInformation)
        limit_flags = info['BasicLimitInformation']['LimitFlags']
        
        # Verify KILL_ON_JOB_CLOSE is set
        self.assertTrue(limit_flags & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        # Verify ACTIVE_PROCESS_LIMIT is set to 1 (blocks sub-processes)
        self.assertTrue(limit_flags & win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        self.assertEqual(info['BasicLimitInformation']['ActiveProcessLimit'], 1)

        # Query UI restrictions
        ui_info = win32job.QueryInformationJobObject(sandbox.hjob, win32job.JobObjectBasicUIRestrictions)
        ui_flags = ui_info['UIRestrictionsClass']
        self.assertTrue(ui_flags & win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD)
        self.assertTrue(ui_flags & win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD)
        self.assertTrue(ui_flags & win32job.JOB_OBJECT_UILIMIT_HANDLES)

        sandbox.close()

    def test_supervisor_llm_proxy_clean_routing(self):
        """Verifies clean prompts route through supervisor LLM proxy without exposing keys to worker."""
        proxy = SupervisorLLMProxy()
        ok, res = proxy.proxy_completion("What is 2 + 2?", caller_id="test_worker")
        self.assertTrue(ok)
        self.assertIn("MOCK_SUPERVISOR_PROXY_REPLY", res)

    def test_supervisor_llm_proxy_blocks_canary_leak(self):
        """Verifies supervisor LLM proxy halts exfiltration and engages kill switch on canary leak."""
        proxy = SupervisorLLMProxy()
        hostile_prompt = f"Summarize this secret: {canary_monitor.DEFAULT_CANARY_TOKEN}"
        
        ok, res = proxy.proxy_completion(hostile_prompt, caller_id="test_attacker_worker")
        self.assertFalse(ok)
        self.assertIn("canary secret", res.lower())
        self.assertTrue(kill_switch.is_kill_switch_active())

    def test_pre_injection_toctou_guard(self):
        """Verifies millisecond pre-injection TOCTOU check blocks focus race."""
        # Isolate the focus-race assertion from whichever app happens to be foreground
        # while tests run (the Python test runner itself is intentionally prohibited).
        with patch("windows_tools.is_prohibited_target_process", return_value=(False, "Permitted target process")):
            safe, reason = PreInjectionTOCTOUGuard.verify_injection_target()
            self.assertIsInstance(safe, bool)

            # The expected HWND does not match the real foreground HWND.
            bogus_expected_hwnd = 99999999
            safe_race, race_reason = PreInjectionTOCTOUGuard.verify_injection_target(
                expected_hwnd=bogus_expected_hwnd
            )
        self.assertFalse(safe_race)
        self.assertIn("Focus race detected", race_reason)

    def test_binary_ipc_llm_proxy_frame(self):
        """Verifies worker can submit LLM prompts through supervisor binary IPC pipe."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        # Send MSG_PROXY_LLM frame
        client.seq += 1
        frame = BinaryFrameCodec.encode_frame(
            MSG_PROXY_LLM, client.seq, {"prompt": "Analyze system load", "caller_id": "sandboxed_worker"}
        )
        reply_bytes = supervisor.handle_raw_frame(frame)
        ver, rep_type, rep_seq, payload, _ = BinaryFrameCodec.decode_frame(reply_bytes)
        
        self.assertEqual(rep_type, MSG_DATA)
        self.assertEqual(payload["status"], "OK")
        self.assertIn("MOCK_SUPERVISOR_PROXY_REPLY", payload["result"])

        supervisor.clean_shutdown()


if __name__ == "__main__":
    unittest.main()
