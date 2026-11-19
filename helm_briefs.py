"""helm_briefs.py - Ready-Made Scheduled Daily Brief Templates.

Provides structured prompt and scheduling templates for morning routines:
- Markets Brief: Weekday market indices (Nifty, Sensex, global), currencies, factual news (strictly zero financial advice).
- AI & Tech Brief: Models, tools, open-source libraries, major releases from the past 24 hours.
- Email / Inbox Brief: Unread messages grouped by urgency (needs reply, security/alerts, general).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

_DATE_RULE = (
    "Use only items dated within the past 24 hours. Explicitly check dates, "
    "cite sources for each item, and state clearly if no new items occurred. Never invent from memory."
)


@dataclass(frozen=True)
class BriefTemplate:
    id: str
    title: str
    description: str
    schedule_prompt: str
    default_time: str
    category: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


BRIEF_TEMPLATES: dict[str, BriefTemplate] = {
    "markets": BriefTemplate(
        id="markets",
        title="Markets Briefing",
        description="Daily market news and movers every weekday morning (information only, no financial advice).",
        schedule_prompt=(
            "Every weekday at 8:30 AM generate my markets brief: search the web for latest Indian and global "
            "market movements (Nifty 50, Sensex, currency, central bank updates). " + _DATE_RULE +
            " Format: 5 concise bullets with numbers, followed by 1 key watchpoint. Facts only."
        ),
        default_time="08:30",
        category="finance"
    ),
    "ai_tech": BriefTemplate(
        id="ai_tech",
        title="AI & Tech Briefing",
        description="New AI models, developer tools, releases, and notable papers from the last day.",
        schedule_prompt=(
            "Every day at 9:00 AM generate my AI and tech brief: search the web for new AI models, tools, "
            "open-source releases, and notable tech news. " + _DATE_RULE +
            " Format: 5 to 7 concise bullets with project names and links."
        ),
        default_time="09:00",
        category="technology"
    ),
    "email_inbox": BriefTemplate(
        id="email_inbox",
        title="Email Inbox Summary",
        description="Unread email summary grouped by priority (read-only, nothing sent or deleted).",
        schedule_prompt=(
            "Every morning at 8:00 AM summarize unread emails: group into 'Needs Reply', 'Important / Alerts', "
            "and 'Newsletters / Low Priority'. List sender and subject in one line. Do not click links or send replies."
        ),
        default_time="08:00",
        category="productivity"
    ),
}


def list_brief_templates() -> list[dict[str, str]]:
    """Returns available daily brief templates."""
    return [t.to_dict() for t in BRIEF_TEMPLATES.values()]


def get_brief_template(template_id: str) -> Optional[BriefTemplate]:
    """Retrieves a specific brief template by ID."""
    return BRIEF_TEMPLATES.get(template_id.lower().strip())
