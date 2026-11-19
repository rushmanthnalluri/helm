"""helm_briefing.py - Proactive Morning Briefing Engine with Quarantined Synthesis.

Features:
- Collects data from calendar, pending tasks, recent meeting action items, system vitals, and durable memory.
- All untrusted input sources are passed through helm_quarantine_reader.py before synthesis.
- Outputs dual representation:
  1. Spoken Audio Script (succinct, natural tone for TTS barge-in).
  2. Rich Markdown Briefing Document with itemized tasks, action items, and hardware vitals.
- Zero physical actuator execution during briefings (READ_ONLY).
- Fully integrated with assistant_timeline and heartbeat_service.
"""

import os
import sys
import time
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import durable_memory
import assistant_timeline
import helm_quarantine_reader

logger = logging.getLogger("helm.briefing")


@dataclass
class BriefingItem:
    category: str
    title: str
    summary: str
    priority: int = 1  # 1 = normal, 2 = high, 3 = critical
    action_required: bool = False
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class BriefingSource(ABC):
    """Abstract collector source for daily briefings."""
    name: str
    returns_untrusted: bool = True
    max_chars: int = 2000

    @abstractmethod
    def fetch(self) -> List[Dict[str, Any]]:
        """Fetches raw items for briefing consideration."""
        pass


class CalendarTaskCollector(BriefingSource):
    name = "calendar_and_tasks"
    returns_untrusted = True

    def fetch(self) -> List[Dict[str, Any]]:
        items = []
        try:
            # Query quick notes or pending tasks from timeline config
            notes = assistant_timeline.quick_notes.get_recent_notes(limit=5)
            for n in notes:
                items.append({
                    "type": "task",
                    "title": n.get("title") or n.get("content", "")[:50],
                    "content": n.get("content", ""),
                    "priority": 2 if "urgent" in n.get("content", "").lower() else 1
                })
        except Exception as e:
            logger.debug("CalendarTaskCollector notice: %s", e)
        return items


class MeetingActionItemCollector(BriefingSource):
    name = "meeting_action_items"
    returns_untrusted = True

    def fetch(self) -> List[Dict[str, Any]]:
        items = []
        try:
            recent_meetings = assistant_timeline.meeting_notes.get_recent_meetings(limit=3)
            for m in recent_meetings:
                m_title = m.get("title", "Recent Meeting")
                actions = m.get("action_items", [])
                for act in actions:
                    items.append({
                        "type": "meeting_action",
                        "title": f"Action from {m_title}",
                        "content": act,
                        "priority": 2
                    })
        except Exception as e:
            logger.debug("MeetingActionItemCollector notice: %s", e)
        return items


class SystemVitalsCollector(BriefingSource):
    name = "workstation_vitals"
    returns_untrusted = False

    def fetch(self) -> List[Dict[str, Any]]:
        items = []
        try:
            vitals = windows_tools.get_system_vitals()
            batt = vitals.get("battery", {})
            batt_pct = batt.get("percent")
            power_plugged = batt.get("power_plugged")

            summary_bits = []
            if batt_pct is not None:
                charging_str = "charging" if power_plugged else "on battery"
                summary_bits.append(f"Battery: {batt_pct}% ({charging_str})")
            mem = vitals.get("memory", {})
            if mem:
                summary_bits.append(f"RAM available: {mem.get('available_gb', '?')} GB")

            items.append({
                "type": "vitals",
                "title": "System Hardware Vitals",
                "content": ", ".join(summary_bits) or "Workstation operational.",
                "priority": 1,
                "vitals_data": vitals
            })
        except Exception as e:
            logger.debug("SystemVitalsCollector notice: %s", e)
        return items


class DurableMemoryCollector(BriefingSource):
    name = "durable_memory"
    returns_untrusted = False

    def fetch(self) -> List[Dict[str, Any]]:
        items = []
        try:
            store = durable_memory.get_default_memory_store()
            if store:
                facts = store.list_facts()
                user_name = facts.get("user_name")
                if user_name:
                    items.append({"type": "user_pref", "title": "User Identity", "content": user_name})
                coffee = facts.get("morning_coffee")
                if coffee:
                    items.append({"type": "user_pref", "title": "Morning Routine", "content": coffee})
        except Exception as e:
            logger.debug("DurableMemoryCollector notice: %s", e)
        return items


class MorningBriefingEngine:
    """Orchestrates multi-source gathering, quarantined sanitization, and briefing synthesis."""

    def __init__(self, reader: Optional[helm_quarantine_reader.QuarantinedReader] = None):
        self.reader = reader or helm_quarantine_reader.QuarantinedReader()
        self.sources: List[BriefingSource] = [
            CalendarTaskCollector(),
            MeetingActionItemCollector(),
            SystemVitalsCollector(),
            DurableMemoryCollector()
        ]

    def register_source(self, source: BriefingSource):
        self.sources.append(source)

    def generate_briefing(self, caller_user_name: Optional[str] = None) -> Dict[str, Any]:
        """Generates a complete, structured morning briefing with audio script and markdown report."""
        collected_items: List[BriefingItem] = []
        active_sources: List[str] = []
        user_name = caller_user_name or "Friend"
        injection_flagged = False

        for src in self.sources:
            try:
                raw_items = src.fetch()
                if raw_items:
                    active_sources.append(src.name)
                for item in raw_items:
                    # Quarantine untrusted sources
                    if src.returns_untrusted:
                        q_res = self.reader.quarantine_text(
                            item.get("content", ""),
                            content_type=item.get("type", "briefing_item"),
                            max_field_len=180
                        )
                        if q_res.injection_flagged:
                            injection_flagged = True
                        clean_summary = q_res.summary
                    else:
                        clean_summary = item.get("content", "")

                    if item.get("type") == "user_pref" and "user_name" in item.get("content", "").lower():
                        # Extract user name if available
                        words = clean_summary.split()
                        if words:
                            user_name = words[-1].rstrip(".")

                    collected_items.append(BriefingItem(
                        category=item.get("type", "general"),
                        title=item.get("title", "Update"),
                        summary=clean_summary,
                        priority=item.get("priority", 1),
                        action_required=item.get("type") == "meeting_action",
                        source=src.name,
                        metadata=item
                    ))
            except Exception as e:
                logger.error("Error gathering from source %s: %s", src.name, e)

        # Sort items: highest priority first
        collected_items.sort(key=lambda x: x.priority, reverse=True)

        # Build Spoken Audio Script (for natural, concise TTS)
        audio_lines = [f"Good morning, {user_name}! Here is your briefing."]
        actions = [it for it in collected_items if it.action_required]
        if actions:
            audio_lines.append(f"You have {len(actions)} pending action item{'s' if len(actions) > 1 else ''} from recent meetings.")
            for act in actions[:2]:
                audio_lines.append(f"• {act.summary}")
        else:
            audio_lines.append("You have no urgent action items pending.")

        vitals_item = next((it for it in collected_items if it.category == "vitals"), None)
        if vitals_item:
            audio_lines.append(f"System status: {vitals_item.summary}.")

        audio_lines.append("I am ready for your first request.")
        audio_script = " ".join(audio_lines)

        # Build Rich Markdown Report
        md_lines = [
            f"# 🌅 Morning Briefing for {user_name}",
            f"*Generated on {time.strftime('%A, %b %d %Y, %I:%M %p')}*",
            "",
            "## 📋 Priorities & Action Items"
        ]
        if actions:
            for act in actions:
                md_lines.append(f"- **{act.title}**: {act.summary}")
        else:
            md_lines.append("- *No urgent action items.*")

        tasks = [it for it in collected_items if it.category == "task"]
        if tasks:
            md_lines.append("\n## 📌 Tasks & Notes")
            for t in tasks:
                md_lines.append(f"- **{t.title}**: {t.summary}")

        if vitals_item:
            md_lines.append("\n## 💻 Workstation Vitals")
            md_lines.append(f"- {vitals_item.summary}")

        md_lines.append("\n## 🔍 Sources")
        md_lines.append(f"- Synthesized from: {', '.join(active_sources) or 'local state'}")

        if injection_flagged:
            md_lines.append("\n> ⚠️ *Note: Potential prompt injection attempts in raw input items were quarantined and neutralized.*")

        markdown_report = "\n".join(md_lines)

        briefing_payload = {
            "title": f"Morning Briefing for {user_name}",
            "generated_at": time.time(),
            "user_name": user_name,
            "items_count": len(collected_items),
            "audio_text": audio_script,
            "markdown": markdown_report,
            "sources": active_sources,
            "injection_flagged": injection_flagged,
            "tainted": any(s.returns_untrusted for s in self.sources if s.name in active_sources)
        }

        # Record event in timeline
        try:
            assistant_timeline.agent_audit_ledger.record_agent_action(
                caller_id="briefing_engine",
                tool_name="helm_generate_briefing",
                tier="READ_ONLY",
                arguments={"user": user_name, "sources": active_sources},
                decision="ALLOW"
            )
        except Exception:
            pass

        return briefing_payload


_GLOBAL_BRIEFING_ENGINE: Optional[MorningBriefingEngine] = None


def get_morning_briefing_engine() -> MorningBriefingEngine:
    global _GLOBAL_BRIEFING_ENGINE
    if _GLOBAL_BRIEFING_ENGINE is None:
        _GLOBAL_BRIEFING_ENGINE = MorningBriefingEngine()
    return _GLOBAL_BRIEFING_ENGINE


def generate_morning_briefing(user_name: Optional[str] = None) -> Dict[str, Any]:
    """Helper entry point for generating morning briefing."""
    engine = get_morning_briefing_engine()
    return engine.generate_briefing(caller_user_name=user_name)
