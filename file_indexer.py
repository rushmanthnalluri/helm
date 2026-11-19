"""Lightweight Local File Search Indexer for Helm.
Indexes filenames and metadata across Desktop, Documents, and Downloads
allowing instant fuzzy file location and remote retrieval via Telegram.
"""
import os
import sqlite3
import time
import contextlib

from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

DEFAULT_INDEXED_ROOTS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
]

EXCLUDED_DIR_NAMES = {
    'node_modules', '.git', '.vscode', '.idea', '__pycache__', 'appdata',
    '$recycle.bin', 'system volume information', '.cache', 'venv', '.env'
}

def format_file_size(size_bytes: int) -> str:
    """Formats bytes into human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024.0, 1)} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{round(size_bytes / (1024.0 * 1024.0), 1)} MB"
    else:
        return f"{round(size_bytes / (1024.0 * 1024.0 * 1024.0), 2)} GB"

def init_index_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                modified_at REAL NOT NULL,
                size_bytes INTEGER NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_name ON file_index(file_name);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_mtime ON file_index(modified_at);
        """)
        conn.commit()

def _index_directory_recursive(dir_path: str, conn, indexed_counter: list, max_files: int = 15000):
    if indexed_counter[0] >= max_files:
        return

    try:
        with os.scandir(dir_path) as it:
            entries = list(it)
    except (PermissionError, FileNotFoundError, OSError):
        return

    subdirs = []
    file_records = []
    for entry in entries:
        try:
            name = entry.name
            if name.startswith('.'):
                continue

            if entry.is_dir(follow_symlinks=False):
                if name.lower() not in EXCLUDED_DIR_NAMES:
                    subdirs.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                stat = entry.stat()
                file_records.append((entry.path, name, float(stat.st_mtime), int(stat.st_size)))
        except (PermissionError, FileNotFoundError, OSError):
            continue

    if file_records:
        conn.executemany(
            "INSERT OR REPLACE INTO file_index (file_path, file_name, modified_at, size_bytes) VALUES (?, ?, ?, ?)",
            file_records
        )
        indexed_counter[0] += len(file_records)

    for sd in subdirs:
        if indexed_counter[0] >= max_files:
            break
        _index_directory_recursive(sd, conn, indexed_counter, max_files)

def build_file_index(roots=None, db_path=None, max_files=15000):
    """Rebuilds the local file index across specified root folders."""
    init_index_db(db_path)
    target_roots = roots or DEFAULT_INDEXED_ROOTS
    counter = [0]

    with get_connection(db_path) as conn:
        # Clear previous records before re-indexing
        conn.execute("DELETE FROM file_index")
        conn.commit()

        for root in target_roots:
            if os.path.exists(root):
                _index_directory_recursive(root, conn, counter, max_files)

        conn.commit()

    return counter[0]

def search_files(query: str, limit: int = 8, db_path=None):
    """Searches indexed files matching the query substring."""
    clean_q = (query or "").strip()
    if not clean_q:
        return []

    init_index_db(db_path)
    pattern = f"%{clean_q}%"
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, file_path, file_name, modified_at, size_bytes FROM file_index "
            "WHERE file_name LIKE ? ORDER BY modified_at DESC LIMIT ?",
            (pattern, int(limit))
        ).fetchall()
        return [dict(r) for r in rows]

def get_file_by_id(file_id: int, db_path=None):
    """Retrieves single file index record by ID."""
    init_index_db(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT id, file_path, file_name, modified_at, size_bytes FROM file_index WHERE id = ?",
            (int(file_id),)
        ).fetchone()
        return dict(row) if row else None
