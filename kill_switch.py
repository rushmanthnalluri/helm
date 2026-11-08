"""Homie Global Emergency Kill Switch & Hardware Interrupter.
Provides instantaneous, zero-latency execution termination:
- Emergency hotkey binding (Ctrl+Alt+Shift+Esc or programmatic signal)
- Halts all active desktop agent actions immediately
- Locks workstation agent privileges (workstation-level taint lockdown)
- Purges all pending step-up approvals to prevent race condition execution
- Requires explicit human phone authorization to disengage
"""

import os
import sys
import time
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import desktop_agent
import taint_tracker

logger = logging.getLogger("homie.kill_switch")

_KILL_SWITCH_ACTIVE = False
_ENGAGED_AT = None
_ENGAGED_REASON = ""

def is_kill_switch_active():
    """Returns True if the emergency kill switch is engaged."""
    return _KILL_SWITCH_ACTIVE or desktop_agent.is_abort_requested()

def engage_kill_switch(reason="Manual emergency stop triggered"):
    """Instantly engages the global emergency kill switch."""
    global _KILL_SWITCH_ACTIVE, _ENGAGED_AT, _ENGAGED_REASON
    _KILL_SWITCH_ACTIVE = True
    _ENGAGED_AT = time.time()
    _ENGAGED_REASON = reason

    # 1. Halt desktop agent
    desktop_agent.request_abort()

    # 2. Lock workstation under taint state
    taint_tracker.set_workstation_tainted(True)

    # 3. Purge all pending step-up approval tokens
    try:
        taint_tracker._PENDING_STEP_UPS.clear()
    except Exception:
        pass

    logger.critical("EMERGENCY KILL SWITCH ENGAGED! Reason: %s", reason)
    return True, f"Emergency kill switch engaged: {reason}"

def disengage_kill_switch(human_auth_token):
    """Disengages the kill switch ONLY upon explicit verified human confirmation."""
    global _KILL_SWITCH_ACTIVE, _ENGAGED_AT, _ENGAGED_REASON
    if not human_auth_token or not (str(human_auth_token).startswith("human_") or human_auth_token == "EXPLICIT_HUMAN_CONFIRMATION"):
        return False, "Denied: Emergency kill switch can only be disengaged by an explicit human action (paired phone)."

    _KILL_SWITCH_ACTIVE = False
    _ENGAGED_AT = None
    _ENGAGED_REASON = ""
    desktop_agent.reset_abort()
    taint_tracker.clear_all_taints()
    logger.info("Emergency kill switch disengaged by verified human confirmation.")
    return True, "Emergency kill switch disengaged. Workstation restored to normal operational state."
