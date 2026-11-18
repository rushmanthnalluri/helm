"""homie_retrospective.py - Workday Narrative & Multi-Session Retrospective Synthesizer.

Synthesizes personal workstation activity into a coherent, structured retrospective:
- Aggregates application dwell time and productivity metrics (focus_tracker)
- Summarizes recorded meeting transcripts and action items (meeting_notes)
- Compiles scratchpad notes and thoughts (quick_notes)
- Summarizes mediated agent tool actions and automation outcomes (agent_audit_ledger)
- Synthesizes an executive narrative suitable for daily standups or weekly reviews
"""

import os
import sys
import time
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import focus_tracker
import meeting_notes
import quick_notes
import agent_audit_ledger
import durable_memory
import homie_focus_mode

logger = logging.getLogger("homie.retrospective")


def build_retrospective_data(lookback_hours: float = 24.0) -> Dict[str, Any]:
    """Aggregates all local workstation evidence across the requested time window."""
    now = time.time()
    cutoff_time = now - (lookback_hours * 3600.0)

    # 1. User preferences / identity
    user_name = "User"
    try:
        mem = durable_memory.get_durable_store()
        stored_name = mem.get_fact("user_name") or mem.get_fact("name")
        if stored_name:
            user_name = stored_name.replace("The user's name is", "").strip()
    except Exception:
        pass

    # 2. Focus & Dwell statistics
    focus_items = []
    total_tracked_seconds = 0
    try:
        raw_focus = focus_tracker.get_focus_report(lookback_hours=max(1, int(lookback_hours)), limit=10)
        if isinstance(raw_focus, list):
            focus_items = raw_focus
            for item in focus_items:
                total_tracked_seconds += item.get("total_seconds", 0)
    except Exception as e:
        logger.debug("Focus report error: %s", e)

    # 3. Meeting transcripts & action items
    meetings = []
    try:
        raw_meetings = meeting_notes.get_recent_meetings(limit=5)
        for m in (raw_meetings or []):
            if m.get("timestamp", 0) >= cutoff_time:
                meetings.append({
                    "title": m.get("title", "Meeting"),
                    "duration": m.get("duration_formatted", ""),
                    "summary": m.get("summary", ""),
                    "action_items": m.get("action_items", [])
                })
    except Exception as e:
        logger.debug("Meeting report error: %s", e)

    # 4. Quick notes
    notes = []
    try:
        raw_notes = quick_notes.get_recent_notes(limit=8)
        for n in (raw_notes or []):
            if n.get("created_at", 0) >= cutoff_time:
                notes.append({
                    "text": n.get("content", ""),
                    "is_pinned": bool(n.get("is_pinned", False))
                })
    except Exception as e:
        logger.debug("Quick notes error: %s", e)

    # 5. Agent actions executed
    actions_count = 0
    tools_used = set()
    try:
        raw_actions = agent_audit_ledger.get_recent_agent_actions(limit=50)
        for act in (raw_actions or []):
            if act.get("timestamp", 0) >= cutoff_time:
                actions_count += 1
                t = act.get("tool")
                if t and not t.startswith("homie_file_witness"):
                    tools_used.add(t)
    except Exception as e:
        logger.debug("Audit actions error: %s", e)

    # 6. Focus session state
    focus_status = homie_focus_mode.get_focus_status()

    return {
        "user_name": user_name,
        "lookback_hours": lookback_hours,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_focus_hours": round(total_tracked_seconds / 3600.0, 2),
        "top_applications": focus_items[:5],
        "meetings_attended": meetings,
        "notes_recorded": notes,
        "agent_automations_run": actions_count,
        "distinct_tools_used": sorted(list(tools_used)),
        "active_focus_session": focus_status if focus_status.get("is_active") else None
    }


def generate_retrospective_markdown(lookback_hours: float = 24.0) -> str:
    """Generates an executive retrospective report formatted in clean Markdown."""
    data = build_retrospective_data(lookback_hours=lookback_hours)
    
    time_label = f"Past {int(lookback_hours)} Hours" if lookback_hours >= 1.0 else f"Past {int(lookback_hours*60)} Minutes"
    lines = [
        f"# [Retrospective] Workstation Retrospective: {data['user_name']}",
        f"*Generated on {data['generated_at']} ({time_label})*",
        "",
        "## Workstation Focus & Productivity"
    ]

    if data["total_focus_hours"] > 0:
        lines.append(f"- **Total Tracked Active Time**: {data['total_focus_hours']} hours")
        lines.append("- **Top Applications**:")
        for app in data["top_applications"]:
            proc = app.get("proc_name", "app")
            dur = app.get("formatted_duration") or f"{int(app.get('total_seconds', 0)//60)}m"
            pct = app.get("percent_of_total", 0)
            lines.append(f"  • **{proc}**: {dur} ({pct}%)")
    else:
        lines.append("- *No application focus history recorded during this interval.*")

    lines.append("")
    lines.append("## Meetings & Discussions")
    if data["meetings_attended"]:
        for m in data["meetings_attended"]:
            lines.append(f"- **{m['title']}** ({m['duration']})")
            if m["summary"]:
                lines.append(f"  *{m['summary']}*")
            if m["action_items"]:
                lines.append("  *Action Items:*")
                for ai in m["action_items"]:
                    lines.append(f"    - [ ] {ai}")
    else:
        lines.append("- *No audio meetings recorded during this interval.*")

    lines.append("")
    lines.append("## Quick Notes & Jotted Thoughts")
    if data["notes_recorded"]:
        for n in data["notes_recorded"]:
            pin = "[Pinned] " if n["is_pinned"] else "• "
            lines.append(f"{pin}{n['text']}")
    else:
        lines.append("- *No quick notes saved during this interval.*")

    lines.append("")
    lines.append("## Agent Automations & Actions")
    lines.append(f"- **Total Automated Actions Executed**: {data['agent_automations_run']}")
    if data["distinct_tools_used"]:
        lines.append(f"- **Tools Exercised**: {', '.join(data['distinct_tools_used'])}")

    return "\n".join(lines)
