"""Active Window Time Tracking and Focus Intelligence for Homie.
Tracks application foreground time, generates daily productivity reports,
and automatically detects fullscreen mode or active meetings for notification suppression.
"""
import os
import time
import sqlite3
import ctypes
from ctypes import wintypes
import threading
import psutil
from db_utils import get_db_connection as get_connection, DEFAULT_DB_PATH, CONFIG_DIR

MEETING_PROCESS_NAMES = {
    'zoom.exe', 'teams.exe', 'msteams.exe', 'slack.exe',
    'webex.exe', 'skype.exe', 'discord.exe'
}

def clear_old_sessions(days: int = 30, db_path=None):
    """Prunes focus sessions older than N days to prevent unbounded DB growth."""
    cutoff = time.time() - (days * 86400)
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM focus_sessions WHERE occurred_at < ?", (cutoff,))
        conn.commit()

def init_focus_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS focus_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_name TEXT NOT NULL,
                window_title TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                occurred_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_focus_occurred ON focus_sessions(occurred_at);
        """)
        conn.commit()
    try:
        clear_old_sessions(days=30, db_path=db_path)
    except Exception:
        pass

def format_duration(seconds: float) -> str:
    """Formats duration in seconds into human-readable representation."""
    secs = int(max(0, seconds))
    if secs < 60:
        return f"{secs}s" if secs > 0 else "< 1m"
    hours = secs // 3600
    minutes = (secs % 3600) // 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

def record_focus_session(app_name: str, window_title: str, duration_seconds: float, occurred_at: float = None, db_path=None):
    """Records a single completed focus session."""
    if duration_seconds < 2.0:
        return None  # Noise filter: drop switches < 2 seconds

    init_focus_db(db_path)
    ts = occurred_at if occurred_at is not None else time.time()
    clean_app = str(app_name).strip() or "Unknown"
    clean_title = str(window_title).strip()[:200]

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO focus_sessions (application_name, window_title, duration_seconds, occurred_at) "
            "VALUES (?, ?, ?, ?)",
            (clean_app, clean_title, float(duration_seconds), float(ts))
        )
        conn.commit()
        return cursor.lastrowid

def get_focus_report(lookback_hours: int = 24, db_path=None, limit: int = 8):
    """Generates an aggregated productivity summary by application for the lookback window."""
    init_focus_db(db_path)
    since_ts = time.time() - (lookback_hours * 3600)

    with get_connection(db_path) as conn:
        rows = conn.execute("""
            SELECT application_name, SUM(duration_seconds) as total_seconds
            FROM focus_sessions
            WHERE occurred_at >= ?
            GROUP BY application_name
            ORDER BY total_seconds DESC
            LIMIT ?
        """, (since_ts, limit)).fetchall()

        total_time_row = conn.execute(
            "SELECT SUM(duration_seconds) as grand_total FROM focus_sessions WHERE occurred_at >= ?",
            (since_ts,)
        ).fetchone()

        grand_total = total_time_row['grand_total'] or 0.0

        results = []
        for r in rows:
            tot = r['total_seconds']
            pct = round((tot / grand_total * 100.0), 1) if grand_total > 0 else 0.0
            results.append({
                'application_name': r['application_name'],
                'total_seconds': tot,
                'formatted_duration': format_duration(tot),
                'percent': pct
            })
        return results

def get_foreground_process_info():
    """Returns (app_name, window_title) of current active foreground window."""
    hwnd = ctypes.windll.user32.GetForegroundWindow()
    if not hwnd:
        return "Unknown", ""

    # Title
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    buff = ctypes.create_unicode_buffer(length + 1)
    ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
    title = buff.value

    # Process Name
    pid = wintypes.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    app_name = "Unknown"
    try:
        proc = psutil.Process(pid.value)
        app_name = proc.name()
    except Exception:
        pass

    return app_name, title

def is_foreground_window_fullscreen_or_meeting():
    """Checks if user is currently in a meeting or fullscreen mode."""
    hwnd = ctypes.windll.user32.GetForegroundWindow()
    if not hwnd:
        return False

    app_name, _ = get_foreground_process_info()
    if app_name.lower() in MEETING_PROCESS_NAMES:
        return True

    # Check fullscreen against screen dimensions
    rect = wintypes.RECT()
    if ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        w = rect.right - rect.left
        h = rect.bottom - rect.top
        sw = ctypes.windll.user32.GetSystemMetrics(0) # SM_CXSCREEN
        sh = ctypes.windll.user32.GetSystemMetrics(1) # SM_CYSCREEN
        # Allow small border threshold
        if w >= sw and h >= sh:
            return True

    return False

class FocusTracker:
    """Background tracker monitoring window switches and recording focus sessions."""
    def __init__(self, poll_interval: float = 1.5, db_path=None):
        self.poll_interval = poll_interval
        self.db_path = db_path
        self.current_app = None
        self.current_title = None
        self.current_start_time = None
        self.keep_running = False
        self._thread = None
        self._lock = threading.Lock()

    def check_switch(self):
        """Checks for active window changes and records completed session."""
        app, title = get_foreground_process_info()
        now = time.time()

        with self._lock:
            if self.current_app is None:
                self.current_app = app
                self.current_title = title
                self.current_start_time = now
                return

            # If foreground window application changed
            if app != self.current_app:
                dur = now - self.current_start_time
                if dur >= 2.0:
                    record_focus_session(
                        app_name=self.current_app,
                        window_title=self.current_title,
                        duration_seconds=dur,
                        occurred_at=self.current_start_time,
                        db_path=self.db_path
                    )
                self.current_app = app
                self.current_title = title
                self.current_start_time = now

    def _loop(self):
        while self.keep_running:
            try:
                self.check_switch()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def start(self):
        if self.keep_running:
            return
        self.keep_running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.keep_running = False
        # Record final session if active
        with self._lock:
            if self.current_app and self.current_start_time:
                dur = time.time() - self.current_start_time
                if dur >= 2.0:
                    record_focus_session(
                        app_name=self.current_app,
                        window_title=self.current_title,
                        duration_seconds=dur,
                        occurred_at=self.current_start_time,
                        db_path=self.db_path
                    )
                self.current_app = None
