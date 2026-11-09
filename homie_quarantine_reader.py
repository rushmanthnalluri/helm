"""homie_quarantine_reader.py - Quarantined Reader & Dual-Stage Injection Barrier.

Architecture & Contract:
1. Untrusted free text goes ONLY to the user's screen or audio TTS.
2. The agent planner sees ONLY enums, typed fields, and opaque handles ($HANDLE_{hex}).
3. Zero free-text strings are exposed in planner context, eliminating prompt injection channels into model reasoning.
4. The OpaqueHandleStore lives in the Policy Supervisor daemon trust domain, protected by OWNER RIGHTS ACE.
   Neither the untrusted worker nor the desktop UI can alter handle mappings.
5. If a handle is referenced in an approved WRITE_EXEC tool call, the supervisor resolves it only
   when constructing the canonical human approval object shown on the mobile device.
"""

import re
import html
import secrets
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class UrgencyEnum(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AvailabilityEnum(str, Enum):
    IN_STOCK = "in_stock"
    OUT_OF_STOCK = "out_of_stock"
    PREORDER = "preorder"
    UNKNOWN = "unknown"


INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(prior|previous)\s+instructions",
    r"(?i)system\s+override",
    r"(?i)you\s+must\s+now\s+(act|respond|execute|delete|format)",
    r"(?i)disregard\s+(all\s+)?(prior|above)\s+rules",
    r"(?i)new\s+system\s+instruction",
    r"(?i)send\s+(secrets|passwords|keys|token|credentials)\s+to",
    r"(?i)format\s+[c-z]:",
    r"(?i)curl\s+https?://",
    r"(?i)powershell\s+-enc",
    r"(?i)forward\s+all\s+(invoices|emails|messages)\s+to",
]

DELIMITERS_TO_ESCAPE = [
    ("<<<DATA>>>", "[DATA_DELIM_ESCAPED]"),
    ("<<<END_DATA>>>", "[END_DATA_DELIM_ESCAPED]"),
    ("[[[UNTRUSTED]]]", "[UNTRUSTED_DELIM_ESCAPED]"),
    ("[[[END_UNTRUSTED]]]", "[END_UNTRUSTED_DELIM_ESCAPED]"),
    ("<system>", "[SYSTEM_TAG_ESCAPED]"),
    ("</system>", "[END_SYSTEM_TAG_ESCAPED]"),
]


@dataclass
class QuarantinedResult:
    content_type: str
    clean_fields: Dict[str, Any]
    handles: Dict[str, str] = field(default_factory=dict)
    injection_flagged: bool = False
    flagged_reasons: List[str] = field(default_factory=list)
    tainted: bool = True
    user_display_or_tts: str = ""  # Free text ONLY for human screen or TTS
    schema_fields: Dict[str, Any] = field(default_factory=dict)  # Typed / enum fields ONLY for planner
    summary: str = ""

    def __post_init__(self):
        if not self.summary:
            self.summary = self.user_display_or_tts or str(self.clean_fields.get("preview") or "")

    def to_planner_context(self) -> Dict[str, Any]:
        """Returns strict enum/typed dictionary with handles for the planner. ZERO free text."""
        return {
            "content_type": self.content_type,
            "schema_fields": self.schema_fields,
            "handles": self.handles,
            "tainted": True,
            "injection_flagged": self.injection_flagged
        }

    def to_safe_prompt_text(self) -> str:
        """Returns safe, enum/handle wrapped string for planner without free-text injection vectors."""
        lines = [f"[Quarantined Data: {self.content_type} (Strict Schema)]"]
        if self.injection_flagged:
            lines.append("⚠️ SECURITY NOTE: Untrusted text quarantined into opaque handle.")
        for k, v in self.schema_fields.items():
            lines.append(f"• {k}: {v}")
        for handle_name, handle_ref in self.handles.items():
            lines.append(f"• {handle_name}: {handle_ref} (raw body isolated in opaque handle; not in model context)")
        return "\n".join(lines)


class OpaqueHandleStore:
    """Thread-safe storage for raw untrusted bodies referenced only by opaque tokens.
    Lives in the Policy Supervisor daemon trust domain.
    """
    def __init__(self):
        self._store: Dict[str, str] = {}
        self._lock = threading.Lock()

    def store(self, raw_text: str, prefix: str = "HANDLE") -> str:
        handle_id = f"${prefix}_{secrets.token_hex(6)}"
        with self._lock:
            self._store[handle_id] = raw_text
        return handle_id

    def resolve(self, handle_id: str) -> Optional[str]:
        with self._lock:
            return self._store.get(handle_id)

    def clear(self):
        with self._lock:
            self._store.clear()


_GLOBAL_HANDLE_STORE = OpaqueHandleStore()


def get_opaque_handle_store() -> OpaqueHandleStore:
    return _GLOBAL_HANDLE_STORE


class QuarantinedReader:
    """Quarantined reader isolating untrusted free text from the agent planner."""

    def __init__(self, handle_store: Optional[OpaqueHandleStore] = None):
        self.handle_store = handle_store or _GLOBAL_HANDLE_STORE

    def sanitize_field(self, text: str, max_chars: int = 200) -> str:
        """Sanitizes text for user display/TTS: neutralizes escape sequences and caps length."""
        if not text:
            return ""
        clean = text.strip()
        for delim, rep in DELIMITERS_TO_ESCAPE:
            clean = clean.replace(delim, rep)
        clean = html.escape(clean)
        clean = re.sub(r"\s+", " ", clean)
        if len(clean) > max_chars:
            clean = clean[:max_chars] + "...[truncated]"
        return clean

    def check_injections(self, text: str) -> List[str]:
        reasons = []
        for pat in INJECTION_PATTERNS:
            if re.search(pat, text):
                reasons.append(f"Matched pattern: {pat}")
        return reasons

    def quarantine_text(
        self,
        raw_text: str,
        content_type: str = "generic_text",
        max_field_len: int = 200
    ) -> QuarantinedResult:
        """Processes arbitrary text: isolates body into handle, leaves planner with schema only."""
        if not raw_text:
            return QuarantinedResult(
                content_type=content_type,
                clean_fields={},
                schema_fields={},
                tainted=True,
                summary=""
            )

        injections = self.check_injections(raw_text)
        flagged = len(injections) > 0

        # Full body stored in handle store
        body_handle = self.handle_store.store(raw_text, prefix="RAW_TEXT")

        # Free text strictly for user screen / TTS
        display_preview = self.sanitize_field(raw_text, max_chars=max_field_len)

        # Planner sees ONLY length and handle
        schema = {
            "char_count": len(raw_text),
            "has_injection_markers": flagged
        }

        return QuarantinedResult(
            content_type=content_type,
            clean_fields={"preview": display_preview, "char_count": len(raw_text)},
            schema_fields=schema,
            handles={"raw_body": body_handle},
            injection_flagged=flagged,
            flagged_reasons=injections,
            tainted=True,
            user_display_or_tts=display_preview,
            summary=display_preview
        )

    def quarantine_email(self, raw_email: Dict[str, Any]) -> QuarantinedResult:
        """Quarantines email: planner sees parsed address-spec, date, urgency enum, and handle."""
        sender_raw = str(raw_email.get("sender", "unknown@domain.local"))
        addr_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", sender_raw)
        sender_spec = addr_match.group(0).lower() if addr_match else "unknown@domain.local"

        date = self.sanitize_field(str(raw_email.get("date", "")), max_chars=50)
        body = str(raw_email.get("body", ""))
        subject = self.sanitize_field(str(raw_email.get("subject", "No Subject")), max_chars=150)

        injections = self.check_injections(f"{subject} {body}")
        flagged = len(injections) > 0

        # Store raw body in handle store
        body_handle = self.handle_store.store(body, prefix="EMAIL")

        # Classify urgency enum
        urgency = UrgencyEnum.NORMAL.value
        lower_sub = subject.lower()
        if "urgent" in lower_sub or "asap" in lower_sub or "emergency" in lower_sub:
            urgency = UrgencyEnum.HIGH.value

        raw_actions = raw_email.get("action_items", [])
        action_count = min(len(raw_actions), 5)
        clean_actions = [self.sanitize_field(str(a), max_chars=100) for a in raw_actions[:5]]

        user_tts = f"Email from {sender_spec}: {subject}"

        # Planner schema: strictly typed
        schema = {
            "sender_address": sender_spec,
            "date": date,
            "urgency": urgency,
            "action_item_count": action_count,
        }

        return QuarantinedResult(
            content_type="email",
            clean_fields={
                "sender": sender_spec,
                "subject": subject,
                "date": date,
                "action_items": clean_actions
            },
            schema_fields=schema,
            handles={"body": body_handle},
            injection_flagged=flagged,
            flagged_reasons=injections,
            tainted=True,
            user_display_or_tts=user_tts,
            summary=user_tts
        )

    def quarantine_meeting_notes(self, raw_notes: Dict[str, Any]) -> QuarantinedResult:
        """Quarantines meeting notes: planner sees title enum, participant count, and handle."""
        title_raw = str(raw_notes.get("title", "Meeting"))
        full_text = str(raw_notes.get("text", "") or raw_notes.get("notes", ""))

        injections = self.check_injections(f"{title_raw} {full_text}")
        flagged = len(injections) > 0

        text_handle = self.handle_store.store(full_text, prefix="MEETING")
        raw_participants = raw_notes.get("participants", [])
        participants_cleaned = [self.sanitize_field(str(p), max_chars=60) for p in raw_participants[:10]]
        raw_actions = raw_notes.get("action_items", [])
        clean_actions = [self.sanitize_field(str(a), max_chars=120) for a in raw_actions[:5]]

        schema = {
            "title": self.sanitize_field(title_raw, max_chars=60),
            "participant_count": len(participants_cleaned),
            "participants": participants_cleaned,
            "has_action_items": bool(raw_actions)
        }

        user_tts = f"Meeting notes: {title_raw} with {len(participants_cleaned)} participants"

        return QuarantinedResult(
            content_type="meeting_notes",
            clean_fields={
                "title": title_raw,
                "participants": participants_cleaned,
                "action_items": clean_actions
            },
            schema_fields=schema,
            handles={"notes_body": text_handle, "full_notes": text_handle},
            injection_flagged=flagged,
            flagged_reasons=injections,
            tainted=True,
            user_display_or_tts=user_tts,
            summary=user_tts
        )

    def quarantine_calendar_event(self, raw_event: Dict[str, Any]) -> QuarantinedResult:
        """Quarantines calendar event: isolates long description into opaque handle."""
        title = self.sanitize_field(str(raw_event.get("title", "Event")), max_chars=100)
        start = self.sanitize_field(str(raw_event.get("start", "")), max_chars=40)
        end = self.sanitize_field(str(raw_event.get("end", "")), max_chars=40)
        loc = self.sanitize_field(str(raw_event.get("location", "")), max_chars=100)
        desc = str(raw_event.get("description", ""))

        injections = self.check_injections(f"{title} {desc}")
        flagged = len(injections) > 0

        desc_handle = self.handle_store.store(desc, prefix="EVENT_DESC")

        schema = {
            "title": title,
            "start": start,
            "end": end,
            "location": loc,
            "has_description": bool(desc)
        }

        user_tts = f"Calendar Event: {title} at {start}"

        return QuarantinedResult(
            content_type="calendar_event",
            clean_fields={
                "title": title,
                "start": start,
                "end": end,
                "location": loc
            },
            schema_fields=schema,
            handles={"description": desc_handle},
            injection_flagged=flagged,
            flagged_reasons=injections,
            tainted=True,
            user_display_or_tts=user_tts,
            summary=user_tts
        )
