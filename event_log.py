"""Shared Event Log for Helm.
Stores system events, notifications, vitals alerts, reminders, and user presence
in a lightweight SQLite database for presence catch-ups and remote briefs.
"""
import os
import sqlite3
import time
from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

def init_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at REAL NOT NULL,
                event_type TEXT NOT NULL,
                event_summary TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_occurred ON event_log(occurred_at);
        """)
        conn.commit()
    # Automated retention maintenance: prune events older than 14 days
    try:
        clear_old_events(days=14, db_path=db_path)
    except Exception:
        pass

def log_event(event_type: str, event_summary: str, occurred_at: float = None, db_path=None):
    """Logs an event to the persistent event log."""
    ts = occurred_at if occurred_at is not None else time.time()
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO event_log (occurred_at, event_type, event_summary) VALUES (?, ?, ?)",
            (float(ts), str(event_type), str(event_summary).strip())
        )
        conn.commit()
        return cursor.lastrowid

def get_events_since(since_timestamp: float, limit: int = 50, db_path=None):
    """Retrieves events recorded since a given Unix timestamp."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, occurred_at, event_type, event_summary FROM event_log "
            "WHERE occurred_at >= ? ORDER BY occurred_at ASC LIMIT ?",
            (float(since_timestamp), int(limit))
        ).fetchall()
        return [dict(r) for r in rows]

def get_recent_events(limit: int = 10, db_path=None):
    """Retrieves the most recent events."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, occurred_at, event_type, event_summary FROM event_log "
            "ORDER BY occurred_at DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
        return [dict(r) for r in rows]

def clear_old_events(days: int = 7, db_path=None):
    """Prunes events older than N days."""
    cutoff = time.time() - (days * 86400)
    init_db(db_path)
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM event_log WHERE occurred_at < ?", (cutoff,))
        conn.commit()
