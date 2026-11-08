"""Homie Semantic Screen Memory & Recall.
Inspired by Screenpipe and Rewind AI, this provides a local-first, privacy-aware
timeline memory layer for Windows:
- Periodically or on-event indexes active foreground window title, process, and text
- Full-text search over everything you looked at, read, or edited
- Privacy filters to automatically exclude banking, password managers, and incognito windows
- Natural language recall: "What was I reading 20 minutes ago?", "Find tracking number on screen"
"""

import os
import sys
import time
import logging
import threading
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils
import windows_tools
import crypto_vault

logger = logging.getLogger("homie.screen_memory")

SENSITIVE_KEYWORDS = [
    "password", "1password", "bitwarden", "lastpass", "keepass", "bank",
    "banking", "incognito", "private browsing", "credit card", "security code"
]

EXCLUDED_APPS = {
    "1password.exe", "bitwarden.exe", "keepass.exe", "lastpass.exe", "tor.exe"
}

def add_excluded_app(proc_name):
    """Adds a process name to the exclusion blacklist."""
    if proc_name:
        EXCLUDED_APPS.add(proc_name.lower().strip())

def get_excluded_apps():
    """Returns the set of excluded application process names."""
    return set(EXCLUDED_APPS)

def is_sensitive(title, proc_name, text=""):
    proc_clean = (proc_name or "").lower().strip()
    if proc_clean in EXCLUDED_APPS or any(app in proc_clean for app in EXCLUDED_APPS):
        return True
    combined = f"{title} {proc_name} {text}".lower()
    return any(k in combined for k in SENSITIVE_KEYWORDS)

def record_screen_event(proc_name, window_title, text_content=None, summary=None, encrypt_at_rest=True):
    if is_sensitive(window_title, proc_name, text_content or ""):
        logger.debug("Skipping sensitive window: %s (%s)", window_title, proc_name)
        return False

    raw_text = text_content or ""
    stored_text = crypto_vault.encrypt(raw_text) if encrypt_at_rest and raw_text else raw_text

    with db_utils.get_db() as conn:
        conn.execute("""
            INSERT INTO screen_timeline (timestamp, proc_name, window_title, text_content, summary)
            VALUES (?, ?, ?, ?, ?)
        """, (time.time(), proc_name or "unknown", window_title or "", stored_text, summary or ""))
        conn.commit()
    return True

def _decrypt_row_text(stored_text):
    if not stored_text:
        return ""
    try:
        return crypto_vault.decrypt(stored_text)
    except Exception:
        return stored_text

def get_recent_timeline(minutes=30, limit=20):
    cutoff = time.time() - (minutes * 60)
    with db_utils.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, proc_name, window_title, text_content, summary
            FROM screen_timeline
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (cutoff, limit))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "timestamp": r[0],
            "proc_name": r[1],
            "window_title": r[2],
            "text_content": _decrypt_row_text(r[3]),
            "summary": r[4],
            "time_str": time.strftime("%H:%M:%S", time.localtime(r[0]))
        })
    return results

def search_screen_history(query, limit=10):
    if not query:
        return []
    q_lower = query.strip().lower()
    
    # Query database and decrypt in memory to evaluate matches across encrypted records
    with db_utils.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, proc_name, window_title, text_content, summary
            FROM screen_timeline
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        rows = cursor.fetchall()

    results = []
    for r in rows:
        decrypted_text = _decrypt_row_text(r[3])
        title = r[2] or ""
        summary = r[4] or ""
        proc = r[1] or ""
        
        if (q_lower in title.lower() or 
            q_lower in decrypted_text.lower() or 
            q_lower in summary.lower() or 
            q_lower in proc.lower()):
            results.append({
                "timestamp": r[0],
                "proc_name": proc,
                "window_title": title,
                "text_content": decrypted_text,
                "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[0]))
            })
            if len(results) >= limit:
                break
    return results

def forget_recent_history(minutes=15):
    """Immediately purges all recorded screen history from the past N minutes.
    Returns the count of purged events.
    """
    cutoff = time.time() - (minutes * 60)
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM screen_timeline WHERE timestamp >= ?", (cutoff,))
        deleted_count = cur.rowcount
        conn.commit()
    logger.info("Purged %d screen history records from the last %d minutes.", deleted_count, minutes)
    return deleted_count

def cleanup_expired_retention(retention_hours=24):
    """Removes historical screen timeline records older than the retention TTL."""
    cutoff = time.time() - (retention_hours * 3600)
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM screen_timeline WHERE timestamp < ?", (cutoff,))
        purged = cur.rowcount
        conn.commit()
    logger.info("Pruned %d expired screen timeline entries older than %d hours.", purged, retention_hours)
    return purged

def summarize_timeline_text(minutes=30):
    events = get_recent_timeline(minutes=minutes, limit=15)
    if not events:
        return f"🖥️ Screen Timeline: No active window history recorded in the last {minutes} minutes."

    lines = [f"🖥️ Screen Timeline (Last {minutes} min):"]
    seen = set()
    for ev in events:
        key = f"{ev['proc_name']}:{ev['window_title']}"
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"• [{ev['time_str']}] {ev['proc_name']} — {ev['window_title']}")
    return "\n".join(lines)

def _monitor_loop(poll_interval=15):
    global _monitor_running
    last_title = ""
    last_proc = ""

    while _monitor_running:
        try:
            fw = windows_tools.get_foreground_window()
            if fw:
                title = fw.get("title", "")
                proc = fw.get("proc_name", "")
                if title and (title != last_title or proc != last_proc):
                    last_title = title
                    last_proc = proc
                    # Read window text if available
                    text_sample = ""
                    try:
                        text_sample = windows_tools.read_window_text(fw.get("hwnd", 0))
                    except Exception:
                        pass
                    record_screen_event(proc, title, text_content=text_sample[:1000] if text_sample else "")
        except Exception as e:
            logger.debug("Screen monitor error: %s", e)
        time.sleep(poll_interval)

def start_screen_monitor(poll_interval=15):
    global _monitor_running, _monitor_thread
    if _monitor_running:
        return True, "Screen memory monitor is already running."

    _monitor_running = True
    _monitor_thread = threading.Thread(target=_monitor_loop, args=(poll_interval,), daemon=True)
    _monitor_thread.start()
    return True, "Screen memory monitor started."

def stop_screen_monitor():
    global _monitor_running
    _monitor_running = False
    return True, "Screen memory monitor stopped."
