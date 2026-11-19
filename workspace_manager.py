"""Workspace Presets and Multi-Window Layout Manager for Helm.
Saves and restores multi-window arrangements across monitors (e.g. 'dev', 'meeting', 'social')
keyed by process names with automatic coordinate restoration.
"""
import os
import time
import json
import sqlite3
import contextlib
import windows_tools

try:
    import win32gui
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

def init_workspace_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS workspace_presets (
                preset_name TEXT PRIMARY KEY,
                layout_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        conn.commit()

def save_workspace_preset(preset_name: str, windows_list=None, db_path=None) -> tuple[bool, str, int]:
    """Captures the positions of currently visible application windows as a named preset."""
    name = (preset_name or "").strip().lower()
    if not name:
        return False, "Preset name cannot be empty.", 0

    init_workspace_db(db_path)

    # Allow passing explicit window list for testing or use live desktop enumeration
    if windows_list is None:
        windows_list = windows_tools.find_windows("")

    if not windows_list:
        return False, "No active application windows found to save.", 0

    layout = []
    seen_procs = set()

    for w in windows_list:
        pname = (w.get('proc_name') or "").strip()
        rect = w.get('rect')
        if not pname or not rect or len(rect) < 4:
            continue

        # Ignore tiny helper hosts
        if pname.lower() in ('textinputhost.exe', 'shellexperiencehost.exe', 'searchapp.exe'):
            continue

        # Keep primary window per process
        if pname.lower() in seen_procs:
            continue
        seen_procs.add(pname.lower())

        layout.append({
            'process_name': pname,
            'title': w.get('title', ''),
            'rect': list(rect)  # [left, top, right, bottom]
        })

    if not layout:
        return False, "No valid application windows found to capture.", 0

    layout_str = json.dumps(layout, indent=2)

    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO workspace_presets (preset_name, layout_json, created_at) VALUES (?, ?, ?)",
            (name, layout_str, time.time())
        )
        conn.commit()

    return True, f"Saved workspace preset '{name}' ({len(layout)} windows captured).", len(layout)

def restore_workspace_preset(preset_name: str, current_windows_list=None, db_path=None) -> tuple[bool, str, dict]:
    """Restores saved window positions for running applications matching the preset."""
    name = (preset_name or "").strip().lower()
    if not name:
        return False, "Preset name cannot be empty.", {}

    init_workspace_db(db_path)

    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT layout_json FROM workspace_presets WHERE preset_name = ?",
            (name,)
        ).fetchone()

    if not row:
        return False, f"Workspace preset '{name}' not found.", {}

    try:
        saved_layout = json.loads(row['layout_json'])
    except Exception as e:
        return False, f"Corrupted workspace preset data: {e}", {}

    if current_windows_list is None:
        current_windows_list = windows_tools.find_windows("")

    # Map current running windows by lower process name
    proc_map = {}
    for w in current_windows_list:
        pn = (w.get('proc_name') or '').strip().lower()
        if pn and pn not in proc_map:
            proc_map[pn] = w

    restored = 0
    missing = []

    for item in saved_layout:
        target_proc = item.get('process_name', '').lower()
        rect = item.get('rect', [])
        if len(rect) < 4:
            continue

        l, t, r, b = rect
        w_width = max(200, r - l)
        w_height = max(150, b - t)

        match = proc_map.get(target_proc)
        if match:
            hwnd = match.get('hwnd')
            if hwnd and WIN32_AVAILABLE:
                try:
                    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                    win32gui.SetWindowPos(
                        hwnd, 0, int(l), int(t), int(w_width), int(w_height),
                        win32con.SWP_NOZORDER | win32con.SWP_SHOWWINDOW
                    )
                except Exception:
                    pass
            restored += 1
        else:
            missing.append(item.get('process_name'))

    total = len(saved_layout)
    details = {
        'restored': restored,
        'total': total,
        'missing': missing
    }

    if missing:
        msg = f"Restored {restored}/{total} windows for '{name}' ({', '.join(missing[:3])} not running)."
    else:
        msg = f"Restored all {restored}/{total} windows for '{name}'."

    return True, msg, details

def get_all_presets(db_path=None) -> list[str]:
    """Returns a list of all saved preset names."""
    init_workspace_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT preset_name FROM workspace_presets ORDER BY preset_name ASC").fetchall()
        return [r['preset_name'] for r in rows]

def delete_preset(preset_name: str, db_path=None) -> bool:
    """Deletes a saved workspace preset."""
    name = (preset_name or "").strip().lower()
    init_workspace_db(db_path)
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM workspace_presets WHERE preset_name = ?", (name,))
        conn.commit()
        return cur.rowcount > 0
