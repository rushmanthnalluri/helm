"""Helm Shadow Mode & Tiered Rate Limiter.
Provides safe staging and runaway loop protection:
- Shadow Mode: Simulates and audits would-be privileged actions without mutating OS state.
- Tiered Rate Limiting: Limits actions per minute to prevent runaway loops or prompt-fatigue DOS.
"""

import os
import sys
import time
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

logger = logging.getLogger("helm.shadow_mode")

_SHADOW_MODE_ACTIVE = False
_CALL_HISTORY = {}  # caller_id -> [timestamps]

def set_shadow_mode(active=True):
    """Enables or disables shadow simulation mode."""
    global _SHADOW_MODE_ACTIVE
    _SHADOW_MODE_ACTIVE = active
    logger.info("Shadow Mode set to: %s", active)

def is_shadow_mode_active():
    """Returns True if shadow mode is currently active."""
    return _SHADOW_MODE_ACTIVE

def check_rate_limit(caller_id, tier="WRITE_EXEC", max_per_minute=30):
    """Enforces per-caller rate limits over a sliding 60-second window."""
    now = time.time()
    history = _CALL_HISTORY.setdefault(caller_id, [])

    # Prune calls older than 60s
    _CALL_HISTORY[caller_id] = [ts for ts in history if now - ts < 60.0]

    if len(_CALL_HISTORY[caller_id]) >= max_per_minute:
        logger.warning("Rate limit exceeded for caller '%s' (%d calls/min)", caller_id, len(_CALL_HISTORY[caller_id]))
        return False, f"Rate limit exceeded: {len(_CALL_HISTORY[caller_id])} calls in the last 60 seconds (max: {max_per_minute})"

    _CALL_HISTORY[caller_id].append(now)
    return True, "Rate limit within budget"

def clear_rate_limits():
    """Resets call histories."""
    _CALL_HISTORY.clear()

def record_simulated_action(caller_id, tool_name, tier, arguments):
    """Simulates an action and logs to agent_audit_ledger with SHADOW_SIMULATED decision."""
    import secrets
    import agent_audit_ledger
    action_id = f"sim_{secrets.token_hex(4)}"
    logger.info("Shadow Mode Simulation: [%s] caller=%s tool=%s", action_id, caller_id, tool_name)
    agent_audit_ledger.record_agent_action(
        caller_id, tool_name, tier, arguments, decision=f"SHADOW_SIMULATED:{action_id}"
    )
    return {"action_id": action_id, "status": "simulated", "tool": tool_name}
