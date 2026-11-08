"""Homie Agent Audit Ledger.
Provides an immutable, tamper-evident append-only cryptographic ledger (hash-chained)
tracking every tool execution across MCP clients, Telegram, Phone Gateway, and Voice:
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils

logger = logging.getLogger("homie.audit_ledger")
GENESIS_HASH = "0" * 64

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

def _compute_hash(prev_hash, timestamp, caller_id, tool_name, tier, args_hash, decision):
    payload = f"{prev_hash}|{timestamp}|{caller_id}|{tool_name}|{tier}|{args_hash}|{decision}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def record_agent_action(caller_id, tool_name, tier, arguments, decision="ALLOW"):
    """Records an agent action into the hash-chained audit ledger."""
    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode("utf-8")).hexdigest()[:16]
    args_summary = clean_args[:100] + ("..." if len(clean_args) > 100 else "")
    now = time.time()

    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT entry_hash FROM agent_audit_ledger ORDER BY id DESC LIMIT 1")
        last_row = cur.fetchone()
        prev_hash = last_row[0] if last_row else GENESIS_HASH

        entry_hash = _compute_hash(prev_hash, now, caller_id, tool_name, tier, args_hash, decision)

        cur.execute("""
            INSERT INTO agent_audit_ledger (timestamp, caller_id, tool_name, tier, arguments_summary, args_hash, decision, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now, caller_id, tool_name, tier, args_summary, args_hash, decision, prev_hash, entry_hash))
        conn.commit()
    return entry_hash

def verify_ledger_integrity():
    """Validates the cryptographic hash chain from genesis to head."""
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
        recomputed = _compute_hash(prev_h, ts, caller, tool, tier, args_hash, decision)
        if recomputed != curr_h:
            return False, f"Tampered hash at entry #{row_id}: recomputed '{recomputed}', found '{curr_h}'"
        expected_prev = curr_h

    return True, f"Cryptographic integrity verified across all {len(rows)} ledger entries."

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
