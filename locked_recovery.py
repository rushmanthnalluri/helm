"""locked_recovery.py - Human Recovery Flow for Supervisor LOCKED State.

Provides a safe, cryptographically authenticated recovery mechanism when the PolicySupervisor
transitions to STATE_LOCKED (e.g. dirty boot, crash-loop threshold exceeded, or kill switch engagement):
- Rejects booleans and unbound bearer tokens. Requires SignedActionApproval from paired hardware device.
- Inspects and surfaces the exact root cause of lockout and unresolved action intents.
- Orderly purges dirty bits (homie_supervisor_dirty.flag) and resets crash history.
- Disengages emergency kill switch with preserve_taint enforcement (prevents unverified taint laundering).
- Re-arms the supervisor into operational STATE_ARMED and bumps the session epoch.
- Records the recovery event and authorizing device identity to the HMAC-SHA256 audit ledger.
"""

import os
import sys
import json
import time
import hashlib
import logging
from typing import Dict, Any, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor
import kill_switch
import taint_tracker
import agent_audit_ledger
import phone_approval_portal

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


def compute_recovery_payload_hash(confirmation_str: str) -> str:
    """Computes deterministic SHA-256 payload hash of recovery confirmation for signature binding."""
    clean = confirmation_str.strip()
    return hashlib.sha256(clean.encode('utf-8')).hexdigest()


def recover_from_locked_state(
    confirmation: str,
    approval: Dict[str, Any],
    supervisor_instance: Any = None,
    clear_taint: bool = False
) -> Tuple[bool, str, Dict[str, Any]]:
    """Performs orderly human recovery from supervisor lockout.
    Requires cryptographically signed action approval object bound to recovery confirmation hash.
    Surfaces and acknowledges unresolved intents, preserves workstation taint, disengages kill switch,
    bumps session epoch, re-arms supervisor, and records event to HMAC audit ledger.
    Returns (success, message, diagnostics).
    """
    clean_conf = (confirmation or "").strip()
    if clean_conf != REQUIRED_CONFIRMATION:
        msg = f"Recovery rejected: Confirmation mismatch. You must provide '{REQUIRED_CONFIRMATION}'."
        logger.warning(msg)
        return False, msg, {}

    # 1. Cryptographically bound approval verification (fails closed: no booleans or test bypasses)
    if not approval or not isinstance(approval, dict):
        msg = "Recovery rejected: Missing or malformed signed action approval object."
        logger.warning(msg)
        return False, msg, {}

    expected_payload_hash = compute_recovery_payload_hash(clean_conf)
    app_ok, app_msg = phone_approval_portal.verify_action_approval(
        approval, "homie_supervisor_recovery", expected_payload_hash
    )
    if not app_ok:
        msg = f"Recovery rejected: Action approval verification failed: {app_msg}"
        logger.warning(msg)
        return False, msg, {}

    diag_before = inspect_lockout_cause()
    actions_taken = []

    # 2. Surface and acknowledge unresolved intents from supervisor
    unresolved_intents = []
    if supervisor_instance and hasattr(supervisor_instance, "check_unresolved_intents"):
        try:
            unresolved_intents = supervisor_instance.check_unresolved_intents()
            actions_taken.append(f"Surfaced and acknowledged {len(unresolved_intents)} unresolved action intents")
        except Exception:
            pass

    # 3. Clean dirty boot marker
    if os.path.exists(homie_supervisor.DIRTY_FLAG_PATH):
        try:
            os.remove(homie_supervisor.DIRTY_FLAG_PATH)
            actions_taken.append("Removed dirty flag file")
        except Exception as e:
            logger.error("Could not remove dirty flag: %s", e)

    # 4. Reset crash loop history after surfacing root cause
    if os.path.exists(homie_supervisor.CRASH_HISTORY_PATH):
        try:
            os.remove(homie_supervisor.CRASH_HISTORY_PATH)
            actions_taken.append(f"Reset crash-loop history (past count: {diag_before.get('crash_count_recent', 0)})")
        except Exception as e:
            logger.error("Could not remove crash history: %s", e)

    # 5. Disengage emergency kill switch while respecting preserve_taint policy
    if kill_switch.is_kill_switch_active():
        kill_switch.disengage_kill_switch("human_operator_verified_recovery", preserve_taint=(not clear_taint))
        actions_taken.append("Disengaged emergency kill switch")

    # 6. Preserve workstation taint across recovery (preventing taint laundering)
    if clear_taint:
        taint_tracker.human_clear_taint("EXPLICIT_HUMAN_CONFIRMATION")
        actions_taken.append("Explicitly cleared workstation taints via authorized human confirmation")
    else:
        actions_taken.append("Preserved workstation taints across recovery")

    # 7. Re-arm supervisor instance and bump session epoch
    if supervisor_instance:
        supervisor_instance.session_epoch = int(time.time())
        supervisor_instance.state = homie_supervisor.STATE_ARMED
        supervisor_instance.lock_reason = ""
        actions_taken.append(f"Transitioned supervisor state to ARMED (bumped epoch: {supervisor_instance.session_epoch})")

    # 8. Reset global ActionBroker
    try:
        import action_broker
        action_broker._GLOBAL_BROKER = None
        actions_taken.append("Reset global ActionBroker")
    except Exception:
        pass

    # 9. Record recovery event to HMAC-SHA256 audit ledger
    try:
        agent_audit_ledger.record_agent_action(
            f"approval_{approval.get('device_id', 'phone')}",
            "homie_supervisor_recovery",
            "ELEVATED_CONFIRM",
            {
                "unresolved_intents_count": len(unresolved_intents),
                "before": diag_before,
                "actions": actions_taken
            },
            decision="RECOVERY_COMPLETED"
        )
    except Exception:
        pass

    summary = f"Supervisor lockout successfully resolved. Actions: {', '.join(actions_taken)}."
    logger.info(summary)
    return True, summary, {"before": diag_before, "actions": actions_taken, "unresolved": unresolved_intents}


def interactive_cli_recovery(approval_provider_func=None):
    """Interactive command-line tool for local workstation operator recovery."""
    print("=" * 65)
    print("=== HOMIE WORKSTATION SUPERVISOR LOCKOUT RECOVERY ===")
    print("=" * 65)
    diag = inspect_lockout_cause()
    print("Current Workstation Diagnostics:")
    print(f" • Dirty Flag Present   : {diag['is_dirty_flag_present']}")
    print(f" • Kill Switch Active   : {diag['is_kill_switch_active']} ({diag['kill_switch_reason']})")
    print(f" • Recent Crashes Count : {diag['crash_count_recent']}")
    print("-" * 65)

    if approval_provider_func:
        approval = approval_provider_func()
    else:
        print("A cryptographically signed approval object from your paired phone is required.")
        print("Please approve the recovery request on your paired device and paste the signed approval JSON:")
        try:
            raw_json = input("Signed Approval JSON: ").strip()
            approval = json.loads(raw_json)
        except Exception as e:
            print(f"[FAILED] Invalid or missing approval JSON: {e}")
            return False

    ok, msg, info = recover_from_locked_state(REQUIRED_CONFIRMATION, approval=approval)
    if ok:
        print(f"\n[SUCCESS] {msg}")
    else:
        print(f"\n[FAILED] {msg}")
    return ok
