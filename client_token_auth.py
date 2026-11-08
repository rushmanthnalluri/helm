"""Homie Per-Client Scoped Revocable Token Manager.
Provides cryptographically secure authentication tokens for MCP clients, IDE plugins,
and remote agents:
- Enforces Principle of Least Privilege: Default scope is strictly READ_ONLY
- Scopes: READ_ONLY, SENSITIVE_READ, WRITE_EXEC, ADMIN
- Time-to-Live (TTL) expiration support
- Instant revocability
- Constant-time secret verification via SHA-256 hash storage
"""

import os
import sys
import time
import json
import secrets
import hashlib
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils

logger = logging.getLogger("homie.token_auth")

VALID_SCOPES = {"READ_ONLY", "SENSITIVE_READ", "WRITE_EXEC", "ADMIN"}

# Tier hierarchy for permission inheritance
TIER_HIERARCHY = {
    "READ_ONLY": 1,
    "SENSITIVE_READ": 2,
    "WRITE_EXEC": 3,
    "ADMIN": 4
}

def init_token_db():
    with db_utils.get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_client_tokens (
                token_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_token_hash ON mcp_client_tokens(token_hash)")
        conn.commit()

init_token_db()

def _hash_token(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()

def create_client_token(client_name, scopes=None, ttl_seconds=86400 * 30):
    """Generates a new scoped token for a client.
    Default scope is strictly READ_ONLY.
    Returns (raw_token_secret, token_metadata).
    """
    if not scopes:
        scopes = ["READ_ONLY"]

    invalid = set(scopes) - VALID_SCOPES
    if invalid:
        raise ValueError(f"Invalid scope(s): {invalid}. Allowed: {VALID_SCOPES}")

    token_id = secrets.token_hex(8)
    secret_key = f"homie_tk_{token_id}_{secrets.token_urlsafe(24)}"
    token_hash = _hash_token(secret_key)
    now = time.time()
    expires_at = (now + ttl_seconds) if ttl_seconds else None

    scopes_json = json.dumps(scopes)

    with db_utils.get_db() as conn:
        conn.execute("""
            INSERT INTO mcp_client_tokens (token_id, client_name, token_hash, scopes, created_at, expires_at, is_revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        """, (token_id, client_name, token_hash, scopes_json, now, expires_at))
        conn.commit()

    meta = {
        "token_id": token_id,
        "client_name": client_name,
        "scopes": scopes,
        "created_at": now,
        "expires_at": expires_at,
        "is_revoked": False
    }
    logger.info("Created client token for '%s' [ID: %s, Scopes: %s]", client_name, token_id, scopes)
    return secret_key, meta

def validate_client_token(secret_key, required_tier="READ_ONLY"):
    """Validates token authenticity, expiration, revocation, and capability tier scope.
    Returns (is_valid, message, token_meta).
    """
    if not secret_key:
        return False, "Missing client authentication token", None

    token_hash = _hash_token(secret_key)
    now = time.time()

    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT token_id, client_name, scopes, created_at, expires_at, is_revoked
            FROM mcp_client_tokens
            WHERE token_hash = ?
        """, (token_hash,))
        row = cur.fetchone()

    if not row:
        return False, "Invalid client authentication token", None

    token_id, client_name, scopes_json, created_at, expires_at, is_revoked = row

    if is_revoked:
        return False, f"Token '{token_id}' has been revoked", None

    if expires_at and now > expires_at:
        return False, f"Token '{token_id}' expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))}", None

    try:
        scopes = json.loads(scopes_json)
    except Exception:
        scopes = ["READ_ONLY"]

    meta = {
        "token_id": token_id,
        "client_name": client_name,
        "scopes": scopes,
        "created_at": created_at,
        "expires_at": expires_at
    }

    # Verify required capability tier
    # ADMIN has access to all tiers
    if "ADMIN" in scopes:
        return True, "Token authenticated with ADMIN scope", meta

    if required_tier not in scopes:
        return False, f"Access denied: Token lacks required capability scope '{required_tier}'. Granted scopes: {scopes}", meta

    return True, f"Token authenticated for '{client_name}' with scope '{required_tier}'", meta

def revoke_client_token(token_id):
    """Immediately revokes an active client token."""
    now = time.time()
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE mcp_client_tokens
            SET is_revoked = 1, revoked_at = ?
            WHERE token_id = ? AND is_revoked = 0
        """, (now, token_id))
        affected = cur.rowcount
        conn.commit()

    if affected > 0:
        logger.warning("Revoked client token: %s", token_id)
        return True, f"Token '{token_id}' has been revoked."
    return False, f"Token '{token_id}' not found or already revoked."

def list_client_tokens():
    """Lists all registered client tokens and their states."""
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT token_id, client_name, scopes, created_at, expires_at, is_revoked, revoked_at
            FROM mcp_client_tokens
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall()

    results = []
    for r in rows:
        results.append({
            "token_id": r[0],
            "client_name": r[1],
            "scopes": json.loads(r[2]) if r[2] else [],
            "created_at": r[3],
            "expires_at": r[4],
            "is_revoked": bool(r[5]),
            "revoked_at": r[6]
        })
    return results
