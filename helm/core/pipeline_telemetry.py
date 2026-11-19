"""Helm Pipeline Latency & Observability Telemetry.
Tracks granular per-stage latency across every interaction:
- Speech-to-text transcription (STT)
- Intent classification & fast-path router
- Windows tool / desktop action execution
- Text-to-speech synthesis (TTS)
- End-to-end total latency

Maintains high-precision timing to safeguard Helm's <50ms local fast-command promise.
"""

import os
import sys
import time
import json
import logging
from collections import deque
from pathlib import Path

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils

logger = logging.getLogger("helm.telemetry")

# In-memory circular buffer for low-overhead real-time stats
_RECENT_EVENTS = deque(maxlen=200)

def init_telemetry_db():
    with db_utils.get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                command_text TEXT,
                path_type TEXT NOT NULL,
                stt_ms REAL DEFAULT 0,
                intent_ms REAL DEFAULT 0,
                action_ms REAL DEFAULT 0,
                tts_ms REAL DEFAULT 0,
                total_ms REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_telem_ts ON pipeline_telemetry(timestamp)")
        conn.commit()

init_telemetry_db()

class LatencyTracker:
    """Context manager / timer for tracking pipeline execution stages."""
    def __init__(self, command_text="", path_type="fast"):
        self.command_text = command_text
        self.path_type = path_type
        self.stt_ms = 0.0
        self.intent_ms = 0.0
        self.action_ms = 0.0
        self.tts_ms = 0.0
        self.start_time = time.perf_counter()
        self._stage_start = None

    def start_stage(self):
        self._stage_start = time.perf_counter()

    def end_stage(self, stage_name):
        if self._stage_start is None:
            return 0.0
        elapsed_ms = (time.perf_counter() - self._stage_start) * 1000.0
        self._stage_start = None
        if stage_name == "stt":
            self.stt_ms = elapsed_ms
        elif stage_name == "intent":
            self.intent_ms = elapsed_ms
        elif stage_name == "action":
            self.action_ms = elapsed_ms
        elif stage_name == "tts":
            self.tts_ms = elapsed_ms
        return elapsed_ms

    def finish(self, path_type=None):
        if path_type:
            self.path_type = path_type
        total_ms = (time.perf_counter() - self.start_time) * 1000.0
        event = {
            "timestamp": time.time(),
            "command": self.command_text[:60],
            "path_type": self.path_type,
            "stt_ms": round(self.stt_ms, 2),
            "intent_ms": round(self.intent_ms, 2),
            "action_ms": round(self.action_ms, 2),
            "tts_ms": round(self.tts_ms, 2),
            "total_ms": round(total_ms, 2)
        }
        _RECENT_EVENTS.append(event)

        # Asynchronously or safely persist to DB
        try:
            with db_utils.get_db() as conn:
                conn.execute("""
                    INSERT INTO pipeline_telemetry (timestamp, command_text, path_type, stt_ms, intent_ms, action_ms, tts_ms, total_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (event["timestamp"], event["command"], event["path_type"], event["stt_ms"], event["intent_ms"], event["action_ms"], event["tts_ms"], event["total_ms"]))
                conn.commit()
        except Exception as e:
            logger.debug("Failed to record telemetry event: %s", e)

        return event

def get_telemetry_summary(limit=50):
    """Returns aggregated latency metrics: p50, p95, avg, fast-path ratio."""
    events = list(_RECENT_EVENTS)[-limit:] if _RECENT_EVENTS else []
    if not events:
        # Fallback to DB
        with db_utils.get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT path_type, stt_ms, intent_ms, action_ms, tts_ms, total_ms
                FROM pipeline_telemetry
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            for r in rows:
                events.append({
                    "path_type": r[0],
                    "stt_ms": r[1],
                    "intent_ms": r[2],
                    "action_ms": r[3],
                    "tts_ms": r[4],
                    "total_ms": r[5]
                })

    if not events:
        return {
            "count": 0,
            "avg_total_ms": 0.0,
            "p50_total_ms": 0.0,
            "p95_total_ms": 0.0,
            "fast_path_pct": 0.0,
            "avg_fast_action_ms": 0.0
        }

    totals = sorted([e["total_ms"] for e in events])
    fast_events = [e for e in events if e.get("path_type") == "fast"]

    n = len(totals)
    p50 = totals[n // 2]
    p95_idx = min(int(n * 0.95), n - 1)
    p95 = totals[p95_idx]
    avg = sum(totals) / n

    fast_ratio = (len(fast_events) / n) * 100.0 if n > 0 else 0.0
    avg_fast_action = sum([e.get("action_ms", 0) for e in fast_events]) / len(fast_events) if fast_events else 0.0

    return {
        "count": n,
        "avg_total_ms": round(avg, 2),
        "p50_total_ms": round(p50, 2),
        "p95_total_ms": round(p95, 2),
        "fast_path_pct": round(fast_ratio, 1),
        "avg_fast_action_ms": round(avg_fast_action, 2)
    }

def format_telemetry_report():
    """Generates a clean markdown telemetry dashboard report."""
    stats = get_telemetry_summary(limit=50)
    if stats["count"] == 0:
        return "⚡ **Helm Latency Telemetry**: No pipeline execution data recorded yet."

    status_icon = "🟢" if stats["avg_fast_action_ms"] < 50.0 else "🟡"

    report = [
        f"⚡ **Helm Pipeline Telemetry & Observability** ({stats['count']} events)",
        f"• **Fast-Path Rate**: {stats['fast_path_pct']}% of requests bypass LLM entirely",
        f"• **Fast Command Latency**: {status_icon} **{stats['avg_fast_action_ms']} ms** (Promise: <50ms)",
        f"• **End-to-End Latency**: Avg: **{stats['avg_total_ms']} ms** | P50: **{stats['p50_total_ms']} ms** | P95: **{stats['p95_total_ms']} ms**",
        "• **Pipeline Stages**: [Mic] ➔ [STT Whisper] ➔ [Intent Router] ➔ [Native Win32] ➔ [TTS SAPI]"
    ]
    return "\n".join(report)
