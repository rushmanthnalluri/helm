"""homie_anticipatory.py - Ambient & Anticipatory Intelligence Engine for Homie.

Delivers proactive, context-aware assistance without waiting to be prompted:
1. Pre-Meeting Prep Cards: Gathers attendee dossiers, past meeting notes, open action items,
   and previous decisions 5 minutes before scheduled meetings.
2. End-of-Day Workday Narrative: Synthesizes daily git activity, meeting logs, learned facts,
   and open reminders into an executive 30-second standup summary.
3. Ambient Desktop Intent Monitor: Detects context cues (clipboard errors, active IDE/browser window)
   and surfaces instant non-disruptive micro-recommendations for the Omnibar/Pill.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import subprocess
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

import homie_knowledge_graph
import meeting_notes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_pre_meeting_card(
    meeting_title: str,
    attendees: Optional[List[str]] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Generates an executive pre-meeting intelligence card.
    Cross-references past meeting notes, attendee dossiers, and open action items.
    """
    clean_title = meeting_title.strip()
    attendee_list = [a.strip() for a in (attendees or []) if a.strip()]

    # If attendees not explicitly passed, try to extract from title (e.g., "1:1 with Alice")
    if not attendee_list:
        match = re.search(r"(?:1:1\s+with|sync\s+with|chat\s+with|meeting\s+with)\s+([A-Za-z0-9_\s]+)", clean_title, re.I)
        if match:
            attendee_list.append(match.group(1).strip())

    # 1. Fetch past meeting history with similar keywords
    past_meetings = []
    try:
        all_recent = meeting_notes.list_recent_meetings(limit=20, db_path=db_path)
        title_keywords = {w.lower() for w in re.findall(r"\w+", clean_title) if len(w) > 3}
        for m in all_recent:
            m_title = m.get("title", "")
            m_keywords = {w.lower() for w in re.findall(r"\w+", m_title) if len(w) > 3}
            # Also check if any attendee name appears in summary or title
            matches_attendee = any(att.lower() in m_title.lower() or att.lower() in m.get("summary", "").lower() for att in attendee_list)
            if (title_keywords and title_keywords.intersection(m_keywords)) or matches_attendee:
                past_meetings.append(m)
    except Exception:
        pass

    # 2. Fetch Knowledge Graph dossiers for attendees
    attendee_dossiers = []
    open_actions = []
    for att in attendee_list:
        try:
            dossier = homie_knowledge_graph.get_entity_dossier(att)
            if dossier.get("ok"):
                attendee_dossiers.append({
                    "name": att,
                    "category": dossier.get("category", "person"),
                    "connections": [r["target"] for r in dossier.get("relationships_out", [])[:4]],
                    "actions": dossier.get("action_items", [])
                })
                for act in dossier.get("action_items", []):
                    open_actions.append(f"{att}: {act.get('context', 'Open deliverable')}")
        except Exception:
            pass

    # 3. Extract relevant takeaways from previous meeting
    last_summary = ""
    last_meeting_date = None
    if past_meetings:
        last_m = past_meetings[0]
        last_summary = last_m.get("summary", "")
        started_at = last_m.get("started_at")
        if started_at:
            last_meeting_date = datetime.fromtimestamp(started_at).strftime("%b %d, %Y")

    # Format human-readable briefing card
    card_lines = [
        f"📋 **Pre-Meeting Briefing: {clean_title}**",
    ]
    if attendee_list:
        card_lines.append(f"👥 **Attendees:** {', '.join(attendee_list)}")

    if last_summary:
        date_str = f" ({last_meeting_date})" if last_meeting_date else ""
        card_lines.append(f"\n💡 **Last Meeting Takeaways{date_str}:**\n{last_summary[:350]}")

    if open_actions:
        card_lines.append("\n📌 **Open Action Items:**")
        for item in open_actions[:5]:
            card_lines.append(f"- [ ] {item}")

    if attendee_dossiers:
        card_lines.append("\n🔍 **Attendee Context:**")
        for d in attendee_dossiers:
            conns = f" (Focus: {', '.join(d['connections'])})" if d['connections'] else ""
            card_lines.append(f"- **{d['name']}**{conns}")

    brief_text = "\n".join(card_lines)

    return {
        "ok": True,
        "title": clean_title,
        "attendees": attendee_list,
        "past_meetings_count": len(past_meetings),
        "last_meeting_date": last_meeting_date,
        "last_summary": last_summary,
        "open_action_items": open_actions,
        "brief_text": brief_text,
        "card_type": "pre_meeting_card"
    }


def generate_eod_narrative(
    workspace_dir: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Generates an End-of-Day Workday Narrative.
    Compiles code modifications, meetings held, facts learned, and open items today.
    """
    ws = workspace_dir or BASE_DIR
    today_start = datetime.combine(date.today(), datetime.min.time()).timestamp()

    # 1. Inspect Git Activity / Modified Files
    git_changes = []
    git_commits = []
    try:
        # Check git status for modified files
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines()[:15]:
                git_changes.append(line.strip())

        # Check git log for today's commits
        res_log = subprocess.run(
            ["git", "log", f"--since=midnight", "--oneline"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=5
        )
        if res_log.returncode == 0 and res_log.stdout.strip():
            git_commits = [c.strip() for c in res_log.stdout.strip().splitlines()[:10]]
    except Exception:
        pass

    # 2. Meetings held today
    meetings_today = []
    try:
        all_meetings = meeting_notes.list_recent_meetings(limit=10, db_path=db_path)
        for m in all_meetings:
            if m.get("started_at", 0) >= today_start:
                meetings_today.append(m)
    except Exception:
        pass

    # 3. Facts or topics learned today
    facts_today = []
    try:
        conn = homie_knowledge_graph._get_connection(db_path)
        rows = conn.execute(
            "SELECT source_name, predicate, target_name FROM relations WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 8",
            (today_start,)
        ).fetchall()
        for r in rows:
            facts_today.append(f"{r['source_name']} {r['predicate'].replace('_', ' ')} {r['target_name']}")
        conn.close()
    except Exception:
        pass

    # Assemble narrative
    narrative_lines = [
        f"🌅 **End-of-Day Standup Narrative — {date.today().strftime('%A, %B %d, %Y')}**\n"
    ]

    # Section 1: Code & Workspace Accomplishments
    narrative_lines.append("🚀 **What Got Done Today:**")
    if git_commits:
        narrative_lines.append("*Commits landed:*")
        for c in git_commits:
            narrative_lines.append(f"- {c}")
    elif git_changes:
        narrative_lines.append(f"*{len(git_changes)} files actively worked on / modified:*")
        for f in git_changes[:8]:
            narrative_lines.append(f"- `{f}`")
    else:
        narrative_lines.append("- Steady development; workspace clean.")

    # Section 2: Meetings & Communications
    narrative_lines.append("\n🤝 **Meetings & Syncs:**")
    if meetings_today:
        for m in meetings_today:
            dur = int(m.get("duration_seconds", 0) // 60)
            narrative_lines.append(f"- **{m.get('title', 'Meeting')}** ({dur} mins): {m.get('summary', '')[:180]}")
    else:
        narrative_lines.append("- No recorded audio meetings today. Focus time preserved.")

    # Section 3: Knowledge Graph Updates
    if facts_today:
        narrative_lines.append("\n🧠 **Knowledge Captured:**")
        for f in facts_today[:5]:
            narrative_lines.append(f"- {f}")

    # Section 4: Tomorrow's Focus
    narrative_lines.append("\n🎯 **Recommended Focus for Tomorrow:**")
    if git_changes:
        narrative_lines.append(f"- Finalize and commit in-progress changes across {len(git_changes)} files.")
    narrative_lines.append("- Review uncompleted action items from your knowledge graph.")

    full_text = "\n".join(narrative_lines)

    return {
        "ok": True,
        "date": date.today().isoformat(),
        "git_commits_count": len(git_commits),
        "git_modified_files": len(git_changes),
        "meetings_today_count": len(meetings_today),
        "facts_today_count": len(facts_today),
        "narrative": full_text
    }


def get_ambient_recommendation(
    active_window_title: str = "",
    clipboard_content: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Analyzes the current desktop context and clipboard to suggest high-value micro-actions."""
    win = (active_window_title or "").lower()
    clip = (clipboard_content or "").strip()

    # Rule 1: Stack trace / error in clipboard
    if clip and any(err_marker in clip.lower() for err_marker in ["traceback (most recent call last):", "exception in thread", "fatal error:", "uncaught typeerror", "syntaxerror:"]):
        err_line = clip.strip().splitlines()[-1][:80]
        return {
            "type": "error_diagnosis",
            "badge": "💡 Fix Suggestion",
            "message": f"Detected stack trace: {err_line}",
            "action_label": "Analyze & Propose Fix",
            "action_command": "analyze_error",
            "payload": clip[:2000]
        }

    # Rule 2: Active PR or Git in browser/IDE
    if "pull request" in win or "github.com" in win or "pull/" in win:
        return {
            "type": "code_review",
            "badge": "🔍 Code Review",
            "message": "GitHub Pull Request detected in active browser tab.",
            "action_label": "Summarize PR & Review",
            "action_command": "review_pr"
        }

    # Rule 3: Calendar / Meeting UI active
    if any(cal in win for cal in ["calendar", "google meet", "zoom", "microsoft teams"]):
        return {
            "type": "meeting_prep",
            "badge": "📅 Meeting Prep",
            "message": "Meeting detected. Click to generate instant attendee prep card.",
            "action_label": "Generate Prep Card",
            "action_command": "pre_meeting_card"
        }

    return None
