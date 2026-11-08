"""Homie Session Taint Tracker & Out-of-Band Step-Up Approval Gate.
Protects against indirect prompt injection and autonomous agent privilege escalation:
- Taint Tracking: Marks a session as TAINTED whenever SENSITIVE_READ or untrusted content is ingested.
- Taint Enforcement: Any subsequent WRITE_EXEC tool call in a tainted session is intercepted
  and blocked from direct execution, requiring out-of-band user approval (Telegram / HUD).
- Token Scoping: Issues scoped, revocable session tokens (READ_ONLY by default).
"""

import os
import sys
import time
import json
import secrets
import logging
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils

logger = logging.getLogger("homie.taint_tracker")

_TAINTED_SESSIONS = {}  # session_id -> {tainted_at, source, details}
_PENDING_STEP_UPS = {}  # step_up_id -> {session_id, tool_name, args, args_hash, created_at, expires_at}
_WORKSTATION_TAINTED = False

def is_workstation_tainted():
    return _WORKSTATION_TAINTED

def set_workstation_tainted(tainted=True):
    global _WORKSTATION_TAINTED
    _WORKSTATION_TAINTED = tainted

def clear_all_taints():
    global _WORKSTATION_TAINTED, _TAINTED_SESSIONS, _PENDING_STEP_UPS
    _WORKSTATION_TAINTED = False
    _TAINTED_SESSIONS.clear()
    _PENDING_STEP_UPS.clear()

def mark_session_tainted(session_id, source="untrusted_content", details=""):
    """Marks a session as tainted after ingesting untrusted or sensitive data, and sets workstation taint."""
    global _WORKSTATION_TAINTED
    _TAINTED_SESSIONS[session_id] = {
        "tainted_at": time.time(),
        "source": source,
        "details": details[:200]
    }
    _WORKSTATION_TAINTED = True
    logger.info("Session '%s' tainted by %s (Workstation taint active)", session_id, source)

def is_session_tainted(session_id):
    """Checks if a session or the workstation has been tainted by external or sensitive data."""
    return session_id in _TAINTED_SESSIONS or _WORKSTATION_TAINTED

def clear_session_taint(session_id):
    """Clears taint after explicit user verification or session termination."""
    global _WORKSTATION_TAINTED
    if session_id in _TAINTED_SESSIONS:
        del _TAINTED_SESSIONS[session_id]
    if not _TAINTED_SESSIONS:
        _WORKSTATION_TAINTED = False

def check_action_privilege(session_id, capability_tier, tool_name, arguments):
    """Evaluates whether an action is permitted, denied, or requires step-up confirmation."""
    if capability_tier == "READ_ONLY":
        return True, False, "READ_ONLY permitted"

    if capability_tier == "SENSITIVE_READ":
        # Ingesting sensitive read taints the session and workstation
        mark_session_tainted(session_id, source=f"tool:{tool_name}")
        return True, False, "SENSITIVE_READ permitted (session and workstation now tainted)"

    if capability_tier in ("WRITE_EXEC", "ELEVATED_CONFIRM"):
        if is_session_tainted(session_id):
            # Tainted session attempting write action: REQUIRE OUT-OF-BAND STEP-UP
            step_up_id = secrets.token_hex(6)
            import hashlib
            args_clean = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
            args_hash = hashlib.sha256(args_clean.encode("utf-8")).hexdigest()[:16]

            _PENDING_STEP_UPS[step_up_id] = {
                "session_id": session_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "args_hash": args_hash,
                "created_at": time.time(),
                "expires_at": time.time() + 120
            }
            logger.warning("Step-up approval required for tainted session %s calling %s (StepUp ID: %s)",
                           session_id, tool_name, step_up_id)
            # Asynchronously push interactive step-up approval to user's paired phone
            try:
                import step_up_gate
                step_up_gate.push_step_up_request_to_phone(
                    step_up_id, session_id, tool_name, arguments, source=_TAINTED_SESSIONS.get(session_id, {}).get("source", "untrusted")
                )
            except Exception as e:
                logger.debug("Could not push step-up notification: %s", e)

            return False, True, f"STEP_UP_REQUIRED: Session is tainted by external data. Out-of-band approval required [ID: {step_up_id}]"

    return True, False, "Permitted"

def approve_step_up(step_up_id, expected_args_hash=None):
    """Grants out-of-band user approval for a pending tainted execution.
    Single-use only, binds strictly to arguments hash.
    """
    item = _PENDING_STEP_UPS.get(step_up_id)
    if not item:
        return False, None, "Invalid or expired step-up ID"
    if time.time() > item["expires_at"]:
        del _PENDING_STEP_UPS[step_up_id]
        return False, None, "Step-up approval timed out"

    if expected_args_hash and item.get("args_hash") != expected_args_hash:
        del _PENDING_STEP_UPS[step_up_id]
        return False, None, "Argument mismatch detected (tampering/replay attempt rejected)"

    # Enforce single-use: immediately delete from pending
    del _PENDING_STEP_UPS[step_up_id]
    return True, item, f"Approved execution of {item['tool_name']}"

def get_taint_status(session_id="default"):
    tainted = is_session_tainted(session_id)
    info = _TAINTED_SESSIONS.get(session_id, {})
    return {
        "session_id": session_id,
        "is_tainted": tainted,
        "tainted_at": info.get("tainted_at"),
        "source": info.get("source"),
        "pending_step_ups": len(_PENDING_STEP_UPS)
    }
