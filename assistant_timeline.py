"""assistant_timeline.py - Unified Opt-In Assistant Timeline for Helm.

Unifies disparate productivity & recall sources into a single coherent timeline:
1. Semantic Screen Memory (window focus, OCR timeline)
2. Focus Tracking (app dwell time & productivity metrics)
3. Meeting Notes (WASAPI loopback audio transcripts)
4. Quick Notes (user-recorded reminders & snippets)
5. Agent Audit Ledger (mediated actions taken by Helm or user)

Features:
- Configurable retention policies (default: 24h) with automated periodic pruning
- Per-application exclusion list (default: password managers, private browsers)
- Grounded "What did I miss?" narrative synthesis
- Opt-in background monitor lifecycle management
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils
import focus_tracker
import meeting_notes
import quick_notes
import semantic_screen_memory
import agent_audit_ledger

logger = logging.getLogger("helm.timeline")

DEFAULT_TIMELINE_CONFIG = {
    "enabled": True,
    "retention_hours": 24,
    "excluded_apps": [
        "1password.exe", "bitwarden.exe", "keepass.exe", "lastpass.exe",
        "tor.exe", "brave_incognito", "chrome_incognito"
    ],
    "poll_interval_seconds": 15
}

_TIMELINE_MONITOR_ACTIVE = False
_TIMELINE_PRUNER_THREAD = None


def get_timeline_config_path() -> Path:
    cfg_dir = Path.home() / ".config" / "helm"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "timeline_config.json"


def load_timeline_config() -> Dict[str, Any]:
    path = get_timeline_config_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
                conf = DEFAULT_TIMELINE_CONFIG.copy()
                conf.update(saved)
                return conf
        except Exception as e:
            logger.error("Failed to load timeline config: %s", e)
    return DEFAULT_TIMELINE_CONFIG.copy()


def save_timeline_config(conf: Dict[str, Any]) -> bool:
    path = get_timeline_config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2)
        # Synchronize exclusions with semantic_screen_memory
        for app in conf.get("excluded_apps", []):
            semantic_screen_memory.add_excluded_app(app)
        return True
    except Exception as e:
        logger.error("Failed to save timeline config: %s", e)
        return False


def add_app_exclusion(app_name: str) -> bool:
    """Adds an application name or process to the timeline exclusion list."""
    conf = load_timeline_config()
    clean = app_name.lower().strip()
    if clean not in conf["excluded_apps"]:
        conf["excluded_apps"].append(clean)
        return save_timeline_config(conf)
    return True


def remove_app_exclusion(app_name: str) -> bool:
    """Removes an application from the timeline exclusion list."""
    conf = load_timeline_config()
    clean = app_name.lower().strip()
    if clean in conf["excluded_apps"]:
        conf["excluded_apps"].remove(clean)
        return save_timeline_config(conf)
    return True


def prune_expired_retention(retention_hours: Optional[int] = None) -> Dict[str, int]:
    """Prunes timeline and memory stores older than the configured retention period."""
    conf = load_timeline_config()
    hours = retention_hours or conf.get("retention_hours", 24)
    cutoff = time.time() - (hours * 3600)
    purged_counts = {}

    # 1. Prune screen timeline
    try:
        purged_counts["screen_timeline"] = semantic_screen_memory.cleanup_expired_retention(retention_hours=hours)
    except Exception as e:
        logger.warning("Screen memory prune error: %s", e)
        purged_counts["screen_timeline"] = 0

    # 2. Prune focus tracker window log
    try:
        with db_utils.get_db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM window_activity WHERE timestamp < ?", (cutoff,))
            purged_counts["focus_activity"] = cur.rowcount
            conn.commit()
    except Exception as e:
        logger.warning("Focus activity prune error: %s", e)
        purged_counts["focus_activity"] = 0

    logger.info("Timeline retention maintenance completed: %s", purged_counts)
    return purged_counts


def get_what_did_i_miss_summary(lookback_hours: int = 4) -> str:
    """Synthesizes a grounded, privacy-preserving narrative summary across all timeline sources."""
    conf = load_timeline_config()
    if not conf.get("enabled", True):
        return "Timeline memory is currently disabled in your preferences."

    cutoff = time.time() - (lookback_hours * 3600)
    sections = []

    # 1. Active Focus & Productivity
    try:
        focus_items = focus_tracker.get_focus_report(lookback_hours=lookback_hours)
        if focus_items:
            focus_lines = [f"📊 **Workstation Focus (Past {lookback_hours}h)**:"]
            for item in focus_items[:5]:
                focus_lines.append(f"• `{item['application_name']}`: {item['formatted_duration']} ({item['percent']}%)")
            sections.append("\n".join(focus_lines))
    except Exception as e:
        logger.debug("Focus summary error: %s", e)

    # 2. Meetings & Audio Transcripts
    try:
        recent_meetings = meeting_notes.get_recent_meetings(limit=3)
        valid_meetings = [m for m in recent_meetings if m.get("started_at", 0) >= cutoff]
        if valid_meetings:
            meet_lines = [f"🎙️ **Recorded Meetings ({len(valid_meetings)})**:"]
            for m in valid_meetings:
                dur = m.get('duration_formatted') or f"{int(m.get('duration_seconds', 0)//60)}m"
                summary = m.get('summary', '').replace('\n', ' ')
                meet_lines.append(f"• **{m.get('title', 'Meeting')}** ({dur}): {summary[:120]}...")
            sections.append("\n".join(meet_lines))
    except Exception as e:
        logger.debug("Meeting summary error: %s", e)

    # 3. Notes & Reminders Added
    try:
        notes = quick_notes.get_all_notes()
        recent_notes = [n for n in notes if n.get("created_at", 0) >= cutoff]
        if recent_notes:
            note_lines = [f"📝 **Notes & Reminders Recorded**:"]
            for n in recent_notes[:5]:
                note_text = n.get("note_text") or n.get("text", "")
                note_lines.append(f"• {note_text}")
            sections.append("\n".join(note_lines))
    except Exception as e:
        logger.debug("Notes summary error: %s", e)

    # 4. Mediated Actions Executed by Helm
    try:
        entries = agent_audit_ledger.query_audit_entries(limit=10)
        recent_actions = [a for a in entries if a.get("timestamp", 0) >= cutoff and a.get("decision") != "DENY"]
        if recent_actions:
            action_lines = [f"🤖 **Automated Actions Executed**:"]
            for act in recent_actions[:4]:
                action_lines.append(f"• [{act.get('caller_id')}] `{act.get('tool_name')}`: {act.get('decision')}")
            sections.append("\n".join(action_lines))
    except Exception as e:
        logger.debug("Audit summary error: %s", e)

    # 5. Screen Timeline Recents
    try:
        screen_events = semantic_screen_memory.get_recent_timeline(minutes=lookback_hours * 60, limit=10)
        if screen_events:
            unique_windows = []
            seen = set()
            for ev in screen_events:
                k = f"{ev['proc_name']}:{ev['window_title']}"
                if k not in seen:
                    seen.add(k)
                    unique_windows.append(f"`{ev['proc_name']}` ({ev['window_title'][:40]})")
            if unique_windows:
                sections.append(f"🖥️ **Active Windows Visited**: " + ", ".join(unique_windows[:6]))
    except Exception as e:
        logger.debug("Screen timeline error: %s", e)

    if not sections:
        return f"🖥️ **Timeline Report**: No significant events or actions recorded in the past {lookback_hours} hours."

    header = f"📅 **Assistant Timeline Summary (Past {lookback_hours} Hours)**\n"
    return header + "\n\n".join(sections)


def start_timeline_monitor(poll_interval: Optional[int] = None) -> bool:
    """Starts background timeline monitoring and periodic retention pruner."""
    global _TIMELINE_MONITOR_ACTIVE, _TIMELINE_PRUNER_THREAD
    conf = load_timeline_config()
    if not conf.get("enabled", True):
        return False

    if _TIMELINE_MONITOR_ACTIVE:
        return True

    # Sync exclusions
    for app in conf.get("excluded_apps", []):
        semantic_screen_memory.add_excluded_app(app)

    interval = poll_interval or conf.get("poll_interval_seconds", 15)
    semantic_screen_memory.start_screen_monitor(poll_interval=interval)

    # Start periodic 1-hour retention pruner
    _TIMELINE_MONITOR_ACTIVE = True

    def _retention_worker():
        while _TIMELINE_MONITOR_ACTIVE:
            try:
                prune_expired_retention()
            except Exception as e:
                logger.debug("Periodic retention prune error: %s", e)
            time.sleep(3600)  # Run maintenance hourly

    _TIMELINE_PRUNER_THREAD = threading.Thread(target=_retention_worker, daemon=True, name="TimelineRetentionWorker")
    _TIMELINE_PRUNER_THREAD.start()
    logger.info("Assistant Timeline monitor and hourly retention pruner started.")
    return True


def stop_timeline_monitor() -> bool:
    global _TIMELINE_MONITOR_ACTIVE
    _TIMELINE_MONITOR_ACTIVE = False
    semantic_screen_memory.stop_screen_monitor()
    logger.info("Assistant Timeline monitor stopped.")
    return True
