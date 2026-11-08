"""Homie Worker Process Confinement & Job Object Sandbox (Batch 18A).

Enforces hardware-grade OS-level confinement on untrusted agent worker processes:
1. Windows Job Object Confinement:
   - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: When the supervisor process closes or dies, the kernel terminates the worker.
   - JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1: Restricts worker from spawning child processes (no cmd/powershell stubs).
   - JobObjectBasicUIRestrictions:
     - UILIMIT_READCLIPBOARD: Blocks worker from reading clipboard directly without supervisor mediation.
     - UILIMIT_WRITECLIPBOARD: Blocks worker from writing clipboard directly.
     - UILIMIT_HANDLES: Blocks access to USER handles outside the job.
     - UILIMIT_DESKTOP: Blocks creating or switching desktops.

2. Supervisor-Hosted LLM Inference Proxy:
   - Network-confined workers cannot reach external LLMs directly.
   - Supervisor proxies model requests, scanning outbound prompts for canaries and injecting credentials at egress.

3. Millisecond Pre-Injection TOCTOU Guard:
   - Resolves target HWND, PID, and executable image immediately before input injection.
   - Aborts if foreground focus changed or targets a prohibited process.
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import canary_monitor
import kill_switch

logger = logging.getLogger("homie.confinement")


class WorkerJobSandbox:
    """Windows Job Object sandbox confining untrusted worker processes."""

    def __init__(self, job_name: Optional[str] = None):
        self.job_name = job_name or f"HomieWorkerJob_{os.getpid()}_{int(time.time()*1000)}"
        self.hjob = None
        self._init_job_object()

    def _init_job_object(self):
        """Initializes and configures the Windows Job Object with strict limits."""
        import win32job
        try:
            self.hjob = win32job.CreateJobObject(None, self.job_name)
            
            # 1. Extended Limit Information: Kill on close & active process limit
            info = win32job.QueryInformationJobObject(self.hjob, win32job.JobObjectExtendedLimitInformation)
            info['BasicLimitInformation']['LimitFlags'] = (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            )
            info['BasicLimitInformation']['ActiveProcessLimit'] = 1
            win32job.SetInformationJobObject(self.hjob, win32job.JobObjectExtendedLimitInformation, info)

            # 2. Basic UI Restrictions: Clipboard, Handles, Desktop
            ui_flags = (
                win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD |
                win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                win32job.JOB_OBJECT_UILIMIT_HANDLES |
                win32job.JOB_OBJECT_UILIMIT_DESKTOP
            )
            ui_info = {'UIRestrictionsClass': ui_flags}
            win32job.SetInformationJobObject(self.hjob, win32job.JobObjectBasicUIRestrictions, ui_info)
            logger.info("Configured Windows Job Object [%s] with KILL_ON_JOB_CLOSE and UI limits", self.job_name)
        except Exception as e:
            logger.error("Failed to initialize Windows Job Object: %s", e)
            self.hjob = None

    def assign_process(self, process_handle_or_pid) -> Tuple[bool, str]:
        """Assigns a worker process to this job object."""
        if not self.hjob:
            return False, "Job object not initialized"

        import win32job
        import win32api
        import win32con

        hproc = None
        close_needed = False
        try:
            if isinstance(process_handle_or_pid, int):
                hproc = win32api.OpenProcess(
                    win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, process_handle_or_pid
                )
                close_needed = True
            else:
                hproc = process_handle_or_pid

            win32job.AssignProcessToJobObject(self.hjob, hproc)
            return True, "Process successfully assigned to sandbox job"
        except Exception as e:
            return False, f"Could not assign process to job: {e}"
        finally:
            if close_needed and hproc:
                try:
                    win32api.CloseHandle(hproc)
                except Exception:
                    pass

    def terminate_all(self, exit_code: int = 1) -> bool:
        """Terminates all processes contained within the job object."""
        if not self.hjob:
            return False
        import win32job
        try:
            win32job.TerminateJobObject(self.hjob, exit_code)
            return True
        except Exception as e:
            logger.error("Error terminating job: %s", e)
            return False

    def close(self):
        """Closes job handle (triggers KILL_ON_JOB_CLOSE if configured)."""
        if self.hjob:
            import win32api
            try:
                win32api.CloseHandle(self.hjob)
            except Exception:
                pass
            self.hjob = None


class SupervisorLLMProxy:
    """Supervisor-hosted LLM inference proxy for network-isolated workers.
    Performs egress inspection, canary scanning, and credential injection.
    """

    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = False):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.mock_mode = mock_mode or (os.environ.get("HOMIE_TEST_ENV") == "1")

    def proxy_completion(self, prompt: str, caller_id: str = "worker") -> Tuple[bool, str]:
        """Validates and executes an LLM completion on behalf of a network-restricted worker."""
        # 1. Multi-channel Canary Scan on outgoing prompt
        leaked, canary_msg = canary_monitor.inspect_egress_payload(prompt)
        if leaked:
            kill_switch.engage_kill_switch(f"Canary exfiltration detected in worker LLM prompt: {canary_msg}")
            return False, f"Security Denial: Outbound prompt contains protected canary secret ({canary_msg})"

        # 2. Rate limiting check
        import shadow_mode
        rate_ok, rate_msg = shadow_mode.check_rate_limit(caller_id, max_per_minute=20)
        if not rate_ok:
            return False, f"Rate limit exceeded: {rate_msg}"

        # 3. Secure execution via ai_engine with supervisor-held credentials
        if self.mock_mode or not self.api_key:
            return True, f"[MOCK_SUPERVISOR_PROXY_REPLY] Successfully routed prompt ({len(prompt)} chars)"

        try:
            import ai_engine
            res = ai_engine.run_gemini(prompt, api_key=self.api_key)
            return True, res
        except Exception as e:
            return False, f"LLM Proxy execution error: {e}"


class PreInjectionTOCTOUGuard:
    """Guards against Time-Of-Check to Time-Of-Use window focus races immediately before input injection."""

    @staticmethod
    def verify_injection_target(expected_hwnd: Optional[int] = None) -> Tuple[bool, str]:
        """Resolves the foreground window and underlying process image at the millisecond of input.
        Returns (True, "OK") if safe, or (False, reason) if foreground focus shifted or targets prohibited image.
        """
        # 1. Check prohibited process
        import windows_tools
        is_prohibited, proc_reason = windows_tools.is_prohibited_target_process()
        if is_prohibited:
            return False, f"TOCTOU Guard: Aborting input injection. Foreground process is prohibited ({proc_reason})"

        # 2. HWND race verification if expected_hwnd was specified
        if expected_hwnd is not None:
            import win32gui
            current_fg = win32gui.GetForegroundWindow()
            if current_fg != expected_hwnd:
                return False, f"TOCTOU Guard: Focus race detected! Expected HWND {expected_hwnd}, but foreground is {current_fg}"

        return True, "Foreground target verified safe"
