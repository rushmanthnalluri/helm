"""Homie Dead-Man's Heartbeat Lease Manager.
Enforces fail-safe execution boundaries:
- Active agents must hold a valid, periodically renewed heartbeat lease (default 5s TTL).
- If an agent hangs, loops, is hijacked, or crashes, the lease lapses.
- The policy dispatcher automatically refuses to execute any WRITE_EXEC action without an active lease.
- Fails safe by default.
"""

import os
import sys
import time
import secrets
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

logger = logging.getLogger("homie.heartbeat")

_ACTIVE_LEASES = {}  # session_id -> {lease_token, expires_at, created_at}
DEFAULT_LEASE_DURATION = 5.0

def acquire_lease(session_id, duration=DEFAULT_LEASE_DURATION):
    """Acquires or renews a dead-man's heartbeat lease for an agent session."""
    now = time.time()
    lease_token = secrets.token_hex(8)
    _ACTIVE_LEASES[session_id] = {
        "lease_token": lease_token,
        "expires_at": now + duration,
        "created_at": now
    }
    return lease_token, now + duration

def renew_lease(session_id, lease_token, duration=DEFAULT_LEASE_DURATION):
    """Renews an existing lease using the session's lease token."""
    now = time.time()
    item = _ACTIVE_LEASES.get(session_id)
    if not item or item["lease_token"] != lease_token:
        return False, "Invalid lease token"
    item["expires_at"] = now + duration
    return True, item["expires_at"]

def is_lease_valid(session_id):
    """Returns True only if the session holds an active, non-expired heartbeat lease."""
    item = _ACTIVE_LEASES.get(session_id)
    if not item:
        return False
    return time.time() <= item["expires_at"]

def revoke_lease(session_id):
    """Immediately revokes an agent's heartbeat lease."""
    if session_id in _ACTIVE_LEASES:
        del _ACTIVE_LEASES[session_id]
        return True
    return False

def clear_all_leases():
    """Clears all active leases."""
    _ACTIVE_LEASES.clear()
