"""Quick Note Taker and Scratchpad for Homie.
Stores quick notes, ideas, code snippets, and scratchpad items with instant pinning,
accessible across the desktop system tray HUD and Telegram remote control.
"""
import os
import time
import sqlite3
import contextlib

from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

def init_notes_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quick_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_text TEXT NOT NULL,
                created_at REAL NOT NULL,
                is_pinned INTEGER DEFAULT 0
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_created ON quick_notes(created_at);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_pinned ON quick_notes(is_pinned);
        """)
        conn.commit()

def save_quick_note(note_text: str, is_pinned: bool = False, db_path=None) -> int:
    """Saves a new note to the scratchpad."""
    text = (note_text or "").strip()
    if not text:
        return 0
    init_notes_db(db_path)
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO quick_notes (note_text, created_at, is_pinned) VALUES (?, ?, ?)",
            (text, time.time(), 1 if is_pinned else 0)
        )
        conn.commit()
        return cur.lastrowid

def get_recent_notes(limit: int = 10, db_path=None) -> list[dict]:
    """Retrieves notes ordered with pinned notes first, then latest created."""
    init_notes_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, note_text, created_at, is_pinned FROM quick_notes "
            "ORDER BY is_pinned DESC, created_at DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
        return [dict(r) for r in rows]

def get_pinned_notes(limit: int = 10, db_path=None) -> list[dict]:
    """Retrieves only pinned notes."""
    init_notes_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, note_text, created_at, is_pinned FROM quick_notes "
            "WHERE is_pinned = 1 ORDER BY created_at DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
        return [dict(r) for r in rows]

def toggle_pin(note_id: int, db_path=None) -> bool:
    """Toggles pin status of a note. Returns new pinned state (True/False)."""
    init_notes_db(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT is_pinned FROM quick_notes WHERE id = ?", (int(note_id),)).fetchone()
        if not row:
            return False
        new_val = 0 if row['is_pinned'] else 1
        conn.execute("UPDATE quick_notes SET is_pinned = ? WHERE id = ?", (new_val, int(note_id)))
        conn.commit()
        return bool(new_val)

def delete_note(note_id: int, db_path=None) -> bool:
    """Deletes a note by ID."""
    init_notes_db(db_path)
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM quick_notes WHERE id = ?", (int(note_id),))
        conn.commit()
        return cur.rowcount > 0

def get_all_notes(db_path=None) -> list[dict]:
    """Retrieves all notes up to 100 recent entries."""
    return get_recent_notes(limit=100, db_path=db_path)

add_note = save_quick_note

