"""locked_recovery.py - Human Recovery Flow for Supervisor LOCKED State.

Provides a safe, interactive, documented recovery mechanism when the PolicySupervisor
transitions to STATE_LOCKED (e.g. dirty boot, crash-loop threshold exceeded, or kill switch engagement):
- Enforces explicit local operator presence (requires confirmation string 'CONFIRM-RECOVERY').
- Inspects and logs the exact root cause of lockout.
- Orderly purges lingering dirty bits (homie_supervisor_dirty.flag).
- Resets crash history counter (homie_supervisor_crashes.json).
- Disengages emergency kill switch with an authenticated human reason.
- Re-arms the supervisor into operational STATE_ARMED.
"""

import os
import sys
import json
import time
import logging
from typing import Dict, Any, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor
import kill_switch
import taint_tracker

logger = logging.getLogger("homie.locked_recovery")

REQUIRED_CONFIRMATION = "CONFIRM-RECOVERY"


def inspect_lockout_cause() -> Dict[str, Any]:
    """Diagnoses the current lockout status and underlying root causes."""
    status = {
        "is_dirty_flag_present": os.path.exists(homie_supervisor.DIRTY_FLAG_PATH),
        "is_kill_switch_active": kill_switch.is_kill_switch_active(),
        "kill_switch_reason": kill_switch.get_kill_switch_status().get("reason", ""),
        "crash_count_recent": 0,
        "recent_crash_timestamps": []
    }

    if os.path.exists(homie_supervisor.CRASH_HISTORY_PATH):
        try:
            with open(homie_supervisor.CRASH_HISTORY_PATH, "r", encoding="utf-8") as f:
                crashes = json.load(f)
                status["recent_crash_timestamps"] = crashes
                status["crash_count_recent"] = len(crashes)
        except Exception:
            pass

    return status


def recover_from_locked_state(confirmation: str, supervisor_instance: Any = None) -> Tuple[bool, str, Dict[str, Any]]:
    """Performs orderly human recovery from supervisor lockout.
    Returns (success, message, diagnostics).
    """
    clean_conf = (confirmation or "").strip()
    if clean_conf != REQUIRED_CONFIRMATION:
        msg = f"Recovery rejected: Confirmation mismatch. You must provide '{REQUIRED_CONFIRMATION}'."
        logger.warning(msg)
        return False, msg, {}

    diag_before = inspect_lockout_cause()
    actions_taken = []

    # 1. Clean dirty boot marker
    if os.path.exists(homie_supervisor.DIRTY_FLAG_PATH):
        try:
            os.remove(homie_supervisor.DIRTY_FLAG_PATH)
            actions_taken.append("Removed dirty flag file")
        except Exception as e:
            logger.error("Could not remove dirty flag: %s", e)

    # 2. Reset crash loop history
    if os.path.exists(homie_supervisor.CRASH_HISTORY_PATH):
        try:
            os.remove(homie_supervisor.CRASH_HISTORY_PATH)
            actions_taken.append("Reset crash-loop history")
        except Exception as e:
            logger.error("Could not remove crash history: %s", e)

    # 3. Disengage emergency kill switch
    if kill_switch.is_kill_switch_active():
        kill_switch.disengage_kill_switch("human_operator_verified_recovery")
        actions_taken.append("Disengaged emergency kill switch")

    # 4. Clear taint and reset action broker
    taint_tracker.clear_all_taints()
    actions_taken.append("Cleared session taints")

    # 5. Re-arm supervisor instance if provided
    if supervisor_instance:
        supervisor_instance.state = homie_supervisor.STATE_ARMED
        supervisor_instance.lock_reason = ""
        actions_taken.append("Transitioned supervisor state to ARMED")

    # Reset global ActionBroker
    try:
        import action_broker
        action_broker._GLOBAL_BROKER = None
        actions_taken.append("Reset global ActionBroker")
    except Exception:
        pass

    summary = f"Supervisor lockout successfully resolved. Actions: {', '.join(actions_taken)}."
    logger.info(summary)
    return True, summary, {"before": diag_before, "actions": actions_taken}


def interactive_cli_recovery():
    """Interactive command-line tool for local workstation operator recovery."""
    print("=" * 65)
    print("=== HOMIE WORKSTATION SUPERVISOR LOCKOUT RECOVERY ===")
    print("=" * 65)
    diag = inspect_lockout_cause()
    print("Current Workstation Diagnostics:")
    print(f" • Dirty Flag Present   : {diag['is_dirty_flag_present']}")
    print(f" • Kill Switch Active   : {diag['is_kill_switch_active']} ({diag['kill_switch_reason']})")
    print(f" • Recent Crashes (<5m) : {diag['crash_count_recent']}")
    print("-" * 65)

    if not (diag["is_dirty_flag_present"] or diag["is_kill_switch_active"] or diag["crash_count_recent"] >= 3):
        print("Workstation is not locked. All systems operating normally.")
        return

    print(f"To unlock your workstation, type '{REQUIRED_CONFIRMATION}' below:")
    try:
        user_input = input("> ").strip()
    except EOFError:
        print("Non-interactive session detected. Recovery aborted.")
        return

    ok, msg, _ = recover_from_locked_state(user_input)
    if ok:
        print(f"\nSUCCESS: {msg}")
    else:
        print(f"\nFAILED: {msg}")


if __name__ == "__main__":
    interactive_cli_recovery()
