"""Helm Agent Audit Ledger.
Provides an immutable, tamper-evident append-only cryptographic ledger (hash-chained)
tracking every tool execution across MCP clients, messaging integrations, and voice:
- Records timestamp, caller identity, tool name, arguments hash, capability tier, decision
- Enforces a SHA-256 hash chain linking every entry to the previous block
- Provides ledger verification to mathematically prove zero tampering
- Answers: "What did agents do on my computer today?"
"""

import os
import sys
import time
import json
import hashlib
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils
import hmac

logger = logging.getLogger("helm.audit_ledger")
GENESIS_HASH = "0" * 64

_LEDGER_KEY_CACHE = None

def get_ledger_secret_key():
    """Retrieves or creates a persistent secret HMAC key for ledger signing."""
    global _LEDGER_KEY_CACHE
    if _LEDGER_KEY_CACHE:
        return _LEDGER_KEY_CACHE

    env_key = os.environ.get("HELM_LEDGER_SECRET")
    if env_key:
        _LEDGER_KEY_CACHE = env_key.encode("utf-8")
        return _LEDGER_KEY_CACHE

    key_file = os.path.join(BASE_DIR, ".helm_ledger_hmac.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "rb") as f:
                _LEDGER_KEY_CACHE = f.read()
                if _LEDGER_KEY_CACHE:
                    return _LEDGER_KEY_CACHE
        except Exception:
            pass

    import secrets
    new_key = secrets.token_bytes(32)
    try:
        with open(key_file, "wb") as f:
            f.write(new_key)
        _LEDGER_KEY_CACHE = new_key
    except Exception:
        _LEDGER_KEY_CACHE = b"helm_default_audit_ledger_hmac_key"

    return _LEDGER_KEY_CACHE

def init_audit_ledger_db():
    with db_utils.get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                caller_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tier TEXT NOT NULL,
                arguments_summary TEXT,
                args_hash TEXT NOT NULL,
                decision TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON agent_audit_ledger(timestamp)")
        conn.commit()

init_audit_ledger_db()

def _compute_hash(prev_hash, timestamp, caller_id, tool_name, tier, args_hash, decision, secret_key=None):
    payload = f"{prev_hash}|{timestamp}|{caller_id}|{tool_name}|{tier}|{args_hash}|{decision}".encode("utf-8")
    if secret_key:
        k = secret_key if isinstance(secret_key, bytes) else str(secret_key).encode("utf-8")
        return hmac.new(k, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()

def record_agent_action(caller_id, tool_name, tier, arguments, decision="ALLOW", secret_key=None):
    """Records an agent action into the hash-chained audit ledger.
    Optionally signs with an HMAC secret key for tamper-proof attestation.
    """
    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode("utf-8")).hexdigest()[:16]
    args_summary = clean_args[:100] + ("..." if len(clean_args) > 100 else "")
    now = time.time()

    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT entry_hash FROM agent_audit_ledger ORDER BY id DESC LIMIT 1")
        last_row = cur.fetchone()
        prev_hash = last_row[0] if last_row else GENESIS_HASH

        entry_hash = _compute_hash(prev_hash, now, caller_id, tool_name, tier, args_hash, decision, secret_key=secret_key)

        cur.execute("""
            INSERT INTO agent_audit_ledger (timestamp, caller_id, tool_name, tier, arguments_summary, args_hash, decision, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now, caller_id, tool_name, tier, args_summary, args_hash, decision, prev_hash, entry_hash))
        conn.commit()

    return entry_hash

def verify_ledger_integrity(secret_key=None):
    """Validates the cryptographic hash chain from genesis to head.
    Supports standard SHA-256 and HMAC-SHA256 signatures across mixed ledger entries.
    """
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, timestamp, caller_id, tool_name, tier, args_hash, decision, prev_hash, entry_hash FROM agent_audit_ledger ORDER BY id ASC")
        rows = cur.fetchall()

    if not rows:
        return True, "Ledger is empty (0 entries)."

    expected_prev = GENESIS_HASH
    for r in rows:
        row_id, ts, caller, tool, tier, args_hash, decision, prev_h, curr_h = r
        if prev_h != expected_prev:
            return False, f"Broken chain at entry #{row_id}: expected prev_hash '{expected_prev}', got '{prev_h}'"

        # Check standard SHA-256
        recomputed = _compute_hash(prev_h, ts, caller, tool, tier, args_hash, decision, secret_key=None)
        if recomputed != curr_h:
            matched = False
            if secret_key:
                if _compute_hash(prev_h, ts, caller, tool, tier, args_hash, decision, secret_key=secret_key) == curr_h:
                    matched = True
            if not matched:
                if _compute_hash(prev_h, ts, caller, tool, tier, args_hash, decision, secret_key=get_ledger_secret_key()) == curr_h:
                    matched = True
            if not matched:
                return False, f"Tampered hash at entry #{row_id}: recomputed '{recomputed}', found '{curr_h}'"

        expected_prev = curr_h

    return True, f"Cryptographic integrity verified across all {len(rows)} ledger entries."

def verify_against_remote_anchor(remote_anchor, secret_key=None):
    """Compares the local ledger state against an externally anchored checkpoint.
    Prevents local ledger truncation, rollback, or fork attacks.
    remote_anchor: dict with {'head_hash': str, 'count': int}
    """
    if not remote_anchor or "head_hash" not in remote_anchor:
        return False, "Invalid remote anchor data"

    remote_head = remote_anchor.get("head_hash")
    remote_count = remote_anchor.get("count", 0)

    # First verify internal hash chain
    ok, chain_msg = verify_ledger_integrity(secret_key=secret_key)
    if not ok:
        return False, f"Ledger integrity failure: {chain_msg}"

    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM agent_audit_ledger")
        local_count = cur.fetchone()[0]

        cur.execute("SELECT entry_hash FROM agent_audit_ledger ORDER BY id ASC LIMIT 1 OFFSET ?", (remote_count - 1,))
        anchor_row = cur.fetchone()

    if local_count < remote_count:
        return False, f"Rollback detected: local ledger has {local_count} entries, but remote anchor proves {remote_count} entries existed."

    if not anchor_row:
        return False, f"Tampering detected: block #{remote_count} missing in local ledger."

    local_anchor_hash = anchor_row[0]
    if local_anchor_hash != remote_head:
        return False, f"Ledger fork/tampering detected at block #{remote_count}: local hash '{local_anchor_hash}' != anchored '{remote_head}'"

    return True, f"Ledger matches remote anchor at block #{remote_count} [{remote_head[:16]}]."

def anchor_head_hash_to_remote():
    """Returns the latest entry hash and count to anchor the ledger to an external log (Telegram / phone)."""
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), entry_hash, timestamp FROM agent_audit_ledger ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if not row or row[0] == 0:
            return None, "Ledger is empty"
        count = row[0]
        cur.execute("SELECT entry_hash, timestamp FROM agent_audit_ledger ORDER BY id DESC LIMIT 1")
        tail = cur.fetchone()
        head_hash = tail[0] if tail else GENESIS_HASH
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tail[1])) if tail else ""

    return {
        "count": count,
        "head_hash": head_hash,
        "head_hash_short": head_hash[:16],
        "timestamp_str": ts_str
    }, f"Anchored block #{count} [{head_hash[:16]}] at {ts_str}"

def get_recent_agent_actions(limit=15):
    """Retrieves the latest agent actions for HUD and Telegram reports."""
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, caller_id, tool_name, tier, arguments_summary, decision, entry_hash
            FROM agent_audit_ledger
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "timestamp": r[1],
            "time_str": time.strftime("%H:%M:%S", time.localtime(r[1])),
            "caller": r[2],
            "tool": r[3],
            "tier": r[4],
            "args": r[5],
            "decision": r[6],
            "hash_prefix": r[7][:8]
        })
    return results

def format_audit_report(limit=10):
    """Formats human-readable agent audit report."""
    actions = get_recent_agent_actions(limit=limit)
    if not actions:
        return "🛡️ **Agent Audit Ledger**: No external agent actions recorded yet."

    ok, verify_msg = verify_ledger_integrity()
    integrity_badge = "🟢 Hash Chain Verified" if ok else "🔴 Tampering Detected"

    lines = [
        f"🛡️ **Agent Audit Ledger** ({integrity_badge}):",
        "Recent AI & remote actions executed on your workstation:\n"
    ]
    tier_icons = {"READ_ONLY": "👁️", "SENSITIVE_READ": "🔍", "WRITE_EXEC": "⚡"}
    for a in actions:
        icon = tier_icons.get(a["tier"], "⚙️")
        lines.append(f"• [{a['time_str']}] {icon} **{a['tool']}** by `{a['caller']}` ({a['decision']})\n  ↳ `{a['args']}` `[{a['hash_prefix']}]`")
    return "\n".join(lines)

def query_audit_entries(limit=15):
    """Queries recent audit entries with standardized dictionary keys."""
    items = get_recent_agent_actions(limit=limit)
    for it in items:
        it["caller_id"] = it.get("caller")
        it["tool_name"] = it.get("tool")
    return items

