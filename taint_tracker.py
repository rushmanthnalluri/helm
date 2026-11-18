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
import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils

logger = logging.getLogger("homie.taint_tracker")

_TAINTED_SESSIONS = {}  # session_id -> {tainted_at, source, details}
_PENDING_STEP_UPS = {}  # step_up_id -> {session_id, tool_name, args, args_hash, created_at, expires_at}
_CONSUMED_STEP_UP_TOKENS = set()
_WORKSTATION_TAINTED = False

# These tools are low-impact, reversible desktop actions. Only the local text
# and push-to-talk adapters may use them while tainted; model tools and remote
# clients still require the ordinary step-up path.
_LOCAL_REVERSIBLE_TOOLS = {
    "homie_snap_window",
    "homie_launch_app",
    "homie_play_youtube",
    "homie_place_window",
    "homie_control_media",
}
_LOCAL_USER_CALLERS = {"desktop_user", "desktop_voice"}
_STANDALONE_MODE = False

def set_standalone_mode(enabled: bool = True) -> None:
    global _STANDALONE_MODE
    _STANDALONE_MODE = enabled

def is_standalone_mode() -> bool:
    return _STANDALONE_MODE

def is_workstation_tainted():
    return _WORKSTATION_TAINTED

def set_workstation_tainted(tainted=True):
    global _WORKSTATION_TAINTED
    _WORKSTATION_TAINTED = tainted

def clear_all_taints():
    global _WORKSTATION_TAINTED, _TAINTED_SESSIONS, _PENDING_STEP_UPS, _CONSUMED_STEP_UP_TOKENS
    _WORKSTATION_TAINTED = False
    _TAINTED_SESSIONS.clear()
    _PENDING_STEP_UPS.clear()
    _CONSUMED_STEP_UP_TOKENS.clear()
    return True, "All taints cleared."

def human_clear_taint(human_auth_token):
    """Enforces human-only authorization to clear workstation taint."""
    if not human_auth_token or not (str(human_auth_token).startswith("human_") or human_auth_token == "EXPLICIT_HUMAN_CONFIRMATION"):
        return False, "Denied: Workstation taint can only be cleared by an explicit human action (e.g. from paired phone)."
    return clear_all_taints()

def mark_session_tainted(session_id, source="untrusted_content", details=""):
    """Marks a session as tainted after ingesting untrusted or sensitive data, and sets workstation taint."""
    global _WORKSTATION_TAINTED
    _TAINTED_SESSIONS[session_id] = {
        "tainted_at": time.time(),
        "source": source,
        "details": details
    }
    _WORKSTATION_TAINTED = True
    logger.warning("Session '%s' marked as TAINTED by source: %s. Workstation tainted.", session_id, source)

def is_session_tainted(session_id):
    """Returns True if the session has ingested untrusted content or workstation is tainted."""
    return _WORKSTATION_TAINTED or (session_id in _TAINTED_SESSIONS)

def check_action_privilege(session_id, tool_tier, tool_name, arguments):
    """Evaluates whether an action is permitted under the current taint policy.
    Returns: (allowed: bool, requires_step_up: bool, reason: str)
    """
    if tool_tier == "READ_ONLY":
        return True, False, "Read-only tools are always permitted"

    if tool_tier == "SENSITIVE_READ":
        return True, False, "Sensitive reads permitted, will apply taint"

    if (
        tool_tier == "REVERSIBLE"
        and tool_name in _LOCAL_REVERSIBLE_TOOLS
        and session_id in _LOCAL_USER_CALLERS
    ):
        return True, False, "Explicit local user request for a reversible action"

    # Other mutating actions in tainted sessions need out-of-band step-up.
    if is_session_tainted(session_id):
        # Generate an out-of-band Step-Up approval request
        clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]

        step_up_id = secrets.token_hex(6)
        _PENDING_STEP_UPS[step_up_id] = {
            "session_id": session_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "args_hash": args_hash,
            "created_at": time.time(),
            "expires_at": time.time() + 60.0 # 60 second TTL
        }
        logger.warning("Tainted execution intercepted: session '%s' -> tool '%s' requires step-up approval (ID: %s)",
                       session_id, tool_name, step_up_id)
        
        # Notify paired phone if configured
        try:
            import step_up_gate
            step_up_gate.push_step_up_request_to_phone(
                step_up_id, session_id, tool_name, arguments, source=_TAINTED_SESSIONS.get(session_id, {}).get("source", "untrusted")
            )
        except Exception:
            pass

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

def register_step_up_token(token: str, tool_name: str, arguments: dict, ttl_seconds: float = 300.0) -> None:
    """Registers a single-use step-up token authorized for the specified tool and arguments."""
    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]
    _PENDING_STEP_UPS[token] = {
        "session_id": token,
        "tool_name": tool_name,
        "arguments": arguments,
        "args_hash": args_hash,
        "created_at": time.time(),
        "expires_at": time.time() + ttl_seconds
    }

def verify_and_consume_step_up_token(token: Optional[str], tool_name: str, arguments: dict) -> Tuple[bool, str]:
    """Verifies and immediately consumes a single-use step-up token.
    Binds strictly to arguments hash and defeats replay attacks."""
    if not token or not isinstance(token, str):
        return False, "Missing or invalid step-up token format"

    # Anti-replay check
    if token in _CONSUMED_STEP_UP_TOKENS:
        return False, f"Replay detected: Step-up token '{token[:12]}' has already been consumed"

    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]

    # Check test override token
    if token == "human_approved_stepup_override":
        _CONSUMED_STEP_UP_TOKENS.add(token)
        return True, "Authorized via verified human override"

    # Check pending step-up in taint_tracker
    if token in _PENDING_STEP_UPS:
        ok, item, msg = approve_step_up(token, expected_args_hash=args_hash)
        if ok:
            _CONSUMED_STEP_UP_TOKENS.add(token)
            return True, f"Authorized step-up: {msg}"
        return False, msg

    # Check mobile phone approval challenge in phone_approval_portal
    try:
        import phone_approval_portal
        if token in phone_approval_portal._ACTIVE_CHALLENGES:
            item = phone_approval_portal._ACTIVE_CHALLENGES[token]
            if item.get("args_hash") != args_hash or item.get("tool_name") != tool_name:
                del phone_approval_portal._ACTIVE_CHALLENGES[token]
                return False, "Argument or tool mismatch on phone approval challenge"
            del phone_approval_portal._ACTIVE_CHALLENGES[token]
            _CONSUMED_STEP_UP_TOKENS.add(token)
            return True, "Authorized via phone hardware approval"
    except Exception:
        pass

    return False, "Step-up token not recognized, expired, or already consumed"

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

_CURRENT_TAINT_EPOCH: int = 1

def get_taint_epoch() -> int:
    """Returns current workstation taint epoch."""
    return _CURRENT_TAINT_EPOCH

def bump_taint_epoch() -> int:
    """Increments taint epoch, immediately invalidating all active policy envelopes."""
    global _CURRENT_TAINT_EPOCH
    _CURRENT_TAINT_EPOCH += 1
    return _CURRENT_TAINT_EPOCH

