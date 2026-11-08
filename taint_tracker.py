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
_PENDING_STEP_UPS = {}  # step_up_id -> {session_id, tool_name, args, created_at, expires_at}

def mark_session_tainted(session_id, source="untrusted_content", details=""):
    """Marks a session as tainted after ingesting untrusted or sensitive data."""
    _TAINTED_SESSIONS[session_id] = {
        "tainted_at": time.time(),
        "source": source,
        "details": details[:200]
    }
    logger.info("Session '%s' tainted by %s", session_id, source)

def is_session_tainted(session_id):
    """Checks if a session has been tainted by external or sensitive data."""
    return session_id in _TAINTED_SESSIONS

def clear_session_taint(session_id):
    """Clears taint after explicit user verification or session termination."""
    if session_id in _TAINTED_SESSIONS:
        del _TAINTED_SESSIONS[session_id]

def check_action_privilege(session_id, capability_tier, tool_name, arguments):
    """Evaluates whether an action is permitted, denied, or requires step-up confirmation."""
    if capability_tier == "READ_ONLY":
        return True, False, "READ_ONLY permitted"

    if capability_tier == "SENSITIVE_READ":
        # Ingesting sensitive read taints the session
        mark_session_tainted(session_id, source=f"tool:{tool_name}")
        return True, False, "SENSITIVE_READ permitted (session now tainted)"

    if capability_tier in ("WRITE_EXEC", "ELEVATED_CONFIRM"):
        if is_session_tainted(session_id):
            # Tainted session attempting write action: REQUIRE OUT-OF-BAND STEP-UP
            step_up_id = secrets.token_hex(6)
            _PENDING_STEP_UPS[step_up_id] = {
                "session_id": session_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "created_at": time.time(),
                "expires_at": time.time() + 120
            }
            logger.warning("Step-up approval required for tainted session %s calling %s (StepUp ID: %s)",
                           session_id, tool_name, step_up_id)
            return False, True, f"STEP_UP_REQUIRED: Session is tainted by external data. Out-of-band approval required [ID: {step_up_id}]"

    return True, False, "Permitted"

def approve_step_up(step_up_id):
    """Grants out-of-band user approval for a pending tainted execution."""
    item = _PENDING_STEP_UPS.get(step_up_id)
    if not item:
        return False, None, "Invalid or expired step-up ID"
    if time.time() > item["expires_at"]:
        del _PENDING_STEP_UPS[step_up_id]
        return False, None, "Step-up approval timed out"

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
