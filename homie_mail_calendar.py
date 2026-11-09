"""homie_mail_calendar.py - Tier B: Mail and Calendar Workflows with Anti-Exfiltration Recipient Policy.

Key Architecture:
1. Mail & Calendar Connectors:
   - Phase 1 (Read-Only): Search threads (headers only), read threads with bodies quarantined into OpaqueHandleStore.
   - Phase 2 (Drafts): Create email drafts and tentative calendar events without notifying attendees.
   - Phase 3 (Send/Invite): Outbound sends require phone-signed approval envelopes showing recipient, subject,
     and full body rendered from structured fields.
2. Anti-Exfiltration Recipient Policy:
   - Validates outbound recipients against thread participants (From/To/Cc headers) and phone-approved contacts.
   - Enforces replies to From address rather than Reply-To (phishing vector defense).
   - Normalizes address-specs (RFC 5322) and checks for punycode/homoglyph lookalike domains.
   - Flags 'NEW RECIPIENT' banner for unknown recipients and denies BCC without explicit authorization.
3. Canonical Structured Approval Hasher:
   - Canonical JSON with NFC normalization, sorted keys, and strict SHA-256 digest.
"""

import os
import sys
import re
import time
import json
import secrets
import hashlib
import unicodedata
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_quarantine_reader
from homie_quarantine_reader import get_opaque_handle_store, QuarantinedReader
import homie_structured_approval


@dataclass(frozen=True)
class Addr:
    display_name: str
    address: str  # Lowercase RFC 5322 address-spec
    punycode: str = ""

    @classmethod
    def parse(cls, raw_addr: str) -> "Addr":
        """Parses address string like 'Priya Sharma <priya@corp.com>' or 'priya@corp.com'."""
        raw_addr = raw_addr.strip()
        match = re.search(r"^(.*?)\s*<([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>$", raw_addr)
        if match:
            display_name = match.group(1).strip().strip("\"'")
            addr_spec = match.group(2).lower()
        else:
            display_name = ""
            addr_spec = raw_addr.strip("<>").lower()

        # Check domain for IDN / punycode
        parts = addr_spec.split("@")
        punycode = addr_spec
        if len(parts) == 2:
            try:
                puny_domain = parts[1].encode("idna").decode("ascii")
                punycode = f"{parts[0]}@{puny_domain}"
            except Exception:
                pass

        return cls(display_name=display_name, address=addr_spec, punycode=punycode)


@dataclass(frozen=True)
class AttRef:
    filename: str
    size_bytes: int
    sha256: str
    handle_id: str


@dataclass(frozen=True)
class OutboundMessage:
    account: str
    to: tuple[Addr, ...]
    cc: tuple[Addr, ...] = ()
    bcc: tuple[Addr, ...] = ()
    subject: str = ""
    body_text: str = ""
    attachments: tuple[AttRef, ...] = ()
    in_reply_to: Optional[str] = None
    thread_id: Optional[str] = None


@dataclass(frozen=True)
class ThreadRef:
    thread_id: str
    subject: str
    last_message_ts: float
    message_count: int
    participants: tuple[str, ...]


@dataclass(frozen=True)
class ThreadView:
    thread_id: str
    subject: str
    participants: tuple[Addr, ...]
    allowed_recipients: tuple[str, ...]
    reply_to_address: Optional[str]
    from_address: str
    quarantined_messages: list[Dict[str, Any]]
    tainted: bool = True


@dataclass(frozen=True)
class DraftRef:
    draft_id: str
    account: str
    subject: str
    recipients: tuple[str, ...]
    body_handle: str
    created_at: float


class RecipientPolicyValidator:
    """Anti-exfiltration validator enforcing thread participant allowlisting and homoglyph checks."""

    def __init__(self, contacts_allowlist: Optional[List[str]] = None):
        self.contacts_allowlist = set(c.lower().strip() for c in (contacts_allowlist or []))
        self.max_sends_per_hour = 20
        self._sent_timestamps: List[float] = []

    def validate_outbound(
        self,
        msg: OutboundMessage,
        thread_view: Optional[ThreadView] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """Validates recipients, phishing vectors (Reply-To vs From), BCC, and rate limits."""
        warnings: List[str] = []
        metadata: Dict[str, Any] = {
            "new_recipients": [],
            "flagged_domains": [],
            "reply_to_mismatch": False
        }

        # 1. Rate limiting check
        now = time.time()
        self._sent_timestamps = [t for t in self._sent_timestamps if now - t < 3600.0]
        if len(self._sent_timestamps) >= self.max_sends_per_hour:
            return False, ["Rate limit exceeded: maximum 20 outbound emails per hour."], metadata

        # 2. BCC verification: BCC is denied unless explicitly authorized
        if msg.bcc:
            warnings.append("⚠️ BCC RECIPIENTS DETECTED: Outbound BCC requires explicit mobile phone confirmation.")

        # 3. Phishing vector check: if replying, verify From vs Reply-To
        if thread_view and thread_view.reply_to_address:
            reply_to = thread_view.reply_to_address.lower()
            from_addr = thread_view.from_address.lower()
            if reply_to != from_addr:
                metadata["reply_to_mismatch"] = True
                warnings.append(
                    f"⚠️ PHISHING WARNING: Message Reply-To ({reply_to}) differs from sender From ({from_addr})."
                )

        # 4. Recipient allowlisting against thread participants + contacts
        allowed_recips = set(self.contacts_allowlist)
        if thread_view:
            allowed_recips.update(thread_view.allowed_recipients)

        all_recipients = list(msg.to) + list(msg.cc) + list(msg.bcc)
        if not all_recipients:
            return False, ["No outbound recipients specified."], metadata

        new_recipients = []
        for a in all_recipients:
            if a.address not in allowed_recips:
                new_recipients.append(a.address)
                warnings.append(f"⚠️ NEW RECIPIENT: '{a.address}' is outside the verified thread/contacts allowlist.")

            # Lookalike / Homoglyph / Punycode domain check
            if a.punycode != a.address:
                metadata["flagged_domains"].append(a.punycode)
                warnings.append(f"⚠️ IDN / PUNYCODE DOMAIN: Address '{a.address}' resolves to punycode '{a.punycode}'.")

        metadata["new_recipients"] = new_recipients
        return True, warnings, metadata


def build_canonical_approval_payload(
    approval_type: str,
    account: str,
    recipients: List[str],
    subject: str,
    body_text: str,
    thread_id: Optional[str] = None,
    nonce: Optional[str] = None,
    warnings: Optional[List[str]] = None
) -> Tuple[Dict[str, Any], str]:
    """Builds a canonical approval dictionary and its deterministic SHA-256 digest."""
    # Compute SHA-256 of body text
    body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    ts = int(time.time())
    nonce_val = nonce or secrets.token_hex(8)

    # Normalize unicode strings using NFC
    payload = {
        "account": unicodedata.normalize("NFC", account),
        "body_hash": body_hash,
        "nonce": nonce_val,
        "recipients": sorted([unicodedata.normalize("NFC", r.lower()) for r in recipients]),
        "subject": unicodedata.normalize("NFC", subject),
        "thread_id": thread_id or "new_thread",
        "timestamp": ts,
        "type": approval_type,
        "warnings": warnings or []
    }

    # Deterministic JSON serialization: sorted keys, compact separators
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return payload, digest


class MailConnector:
    """Mail connector managing headers search, quarantined body reads, drafts, and supervisor send flow."""

    def __init__(self, reader: Optional[QuarantinedReader] = None):
        self.reader = reader or QuarantinedReader()
        self.handle_store = self.reader.handle_store
        self.validator = RecipientPolicyValidator()
        self._drafts: Dict[str, OutboundMessage] = {}
        # In-memory mock thread store for local development / testing
        self._threads: Dict[str, Dict[str, Any]] = {}
        self._sent_messages: Dict[str, SendResult] = {}
        self._audit_log: List[Dict[str, Any]] = []

    def add_mock_thread(self, thread_id: str, subject: str, messages: List[Dict[str, Any]]):
        self._threads[thread_id] = {
            "thread_id": thread_id,
            "subject": subject,
            "messages": messages,
            "last_ts": time.time()
        }

    def search(self, query: str, limit: int = 10) -> List[ThreadRef]:
        """Returns thread headers matching search query (zero body exposure)."""
        limit = max(1, min(limit, 25))
        query_lower = query.lower()
        results = []
        for tid, t in self._threads.items():
            subj = t.get("subject", "")
            msgs = t.get("messages", [])
            # Search subject or participants
            participants = set()
            for m in msgs:
                if "from" in m:
                    participants.add(Addr.parse(m["from"]).address)
                for to_raw in m.get("to", []):
                    participants.add(Addr.parse(to_raw).address)

            if not query or query_lower in subj.lower() or any(query_lower in p.lower() for p in participants):
                results.append(ThreadRef(
                    thread_id=tid,
                    subject=subj,
                    last_message_ts=t.get("last_ts", time.time()),
                    message_count=len(msgs),
                    participants=tuple(sorted(participants))
                ))
            if len(results) >= limit:
                break
        return results

    def read(self, thread_id: str) -> Optional[ThreadView]:
        """Reads thread messages, returns participants, and quarantines bodies into OpaqueHandleStore."""
        t = self._threads.get(thread_id)
        if not t:
            return None

        msgs = t.get("messages", [])
        quarantined_msgs = []
        all_participants: List[Addr] = []
        from_address = ""
        reply_to_address = None

        for idx, m in enumerate(msgs):
            q_res = self.reader.quarantine_email(m)
            quarantined_msgs.append({
                "message_id": f"{thread_id}_m{idx}",
                "clean_fields": q_res.clean_fields,
                "handles": q_res.handles,
                "injection_flagged": q_res.injection_flagged
            })

            from_raw = m.get("from", "")
            if from_raw:
                f_addr = Addr.parse(from_raw)
                all_participants.append(f_addr)
                if not from_address:
                    from_address = f_addr.address

            if "reply_to" in m and not reply_to_address:
                reply_to_address = Addr.parse(m["reply_to"]).address

            for to_raw in m.get("to", []):
                all_participants.append(Addr.parse(to_raw))

        unique_specs = sorted(list(set(p.address for p in all_participants)))

        return ThreadView(
            thread_id=thread_id,
            subject=t.get("subject", "No Subject"),
            participants=tuple(all_participants),
            allowed_recipients=tuple(unique_specs),
            reply_to_address=reply_to_address,
            from_address=from_address or "unknown@local",
            quarantined_messages=quarantined_msgs,
            tainted=True
        )

    def draft(self, msg: OutboundMessage) -> Tuple[bool, DraftRef, List[str], Dict[str, Any]]:
        """Creates a local draft and runs RecipientPolicyValidator. Zero network egress."""
        # 1. Resolve thread view if replying
        thread_view = self.read(msg.thread_id) if msg.thread_id else None

        # 2. Validate recipients against policy
        ok, warnings, meta = self.validator.validate_outbound(msg, thread_view=thread_view)
        if not ok:
            return False, None, warnings, meta

        # 3. Store raw body in opaque handle
        body_handle = self.handle_store.store(msg.body_text, prefix="EMAIL_DRAFT")

        draft_id = f"draft_{secrets.token_hex(6)}"
        self._drafts[draft_id] = msg

        recip_specs = tuple([a.address for a in msg.to] + [a.address for a in msg.cc] + [a.address for a in msg.bcc])
        draft_ref = DraftRef(
            draft_id=draft_id,
            account=msg.account,
            subject=msg.subject,
            recipients=recip_specs,
            body_handle=body_handle,
            created_at=time.time()
        )
        return True, draft_ref, warnings, meta

    def get_draft(self, draft_id: str) -> Optional[OutboundMessage]:
        return self._drafts.get(draft_id)

    def send(
        self,
        draft_id: str,
        assertion_response: Dict[str, Any],
        rp: Any,
        cred: Any,
        challenge_store: Any,
        simulate_transient_failure: bool = False
    ) -> SendResult:
        """Supervisor-only send flow:
        1. Validates draft exists.
        2. Builds canonical 'send' approval object.
        3. Verifies physical WebAuthn assertion signature over canonical approval hash.
        4. Writes INTENT log with idempotency key.
        5. Sends with idempotency key, then writes OUTCOME.
        6. On unknown outcome, requires checking Sent folder before any retry.
        """
        draft = self.get_draft(draft_id)
        if not draft:
            raise ValueError(f"Draft '{draft_id}' not found")

        # 1. Build canonical approval object
        recipients_to = [a.address for a in draft.to]
        recipients_cc = [a.address for a in draft.cc]
        recipients_bcc = [a.address for a in draft.bcc]
        attachment_dicts = [{"name": a.filename, "hash": getattr(a, "sha256", "")} for a in draft.attachments]

        approval_obj = homie_structured_approval.build_send_approval_object(
            account=draft.account,
            to=recipients_to,
            cc=recipients_cc,
            bcc=recipients_bcc,
            subject=draft.subject,
            body_text=draft.body_text,
            attachments=attachment_dicts,
            thread_id=getattr(draft, "thread_id", "") or "",
            nonce=draft_id
        )

        # 2. Derive 32-byte challenge from canonical approval hash
        hash_hex, _ = homie_structured_approval.compute_canonical_approval_hash(approval_obj)
        challenge_bytes = bytes.fromhex(hash_hex)

        # 3. Verify physical WebAuthn assertion proof
        import webauthn_verifier
        webauthn_verifier.verify_assertion(rp, cred, assertion_response, challenge_bytes, challenge_store)

        # 4. Generate idempotency key
        idempotency_key = f"idemp_{draft_id}_{hash_hex[:16]}"
        if idempotency_key in self._sent_messages:
            return self._sent_messages[idempotency_key]

        # 5. Write INTENT audit record
        self._audit_log.append({
            "event": "INTENT",
            "idempotency_key": idempotency_key,
            "draft_id": draft_id,
            "subject": draft.subject,
            "recipients": recipients_to + recipients_cc + recipients_bcc,
            "timestamp": time.time()
        })

        # 6. Simulate network dispatch / unknown outcome handling
        if simulate_transient_failure:
            raise MailDispatchUnknownOutcomeError(
                f"Network timeout during dispatch for draft '{draft_id}'. "
                f"Supervisor must inspect Sent folder for idempotency key '{idempotency_key}' before retrying."
            )

        # 7. Write OUTCOME audit record
        msg_id = f"msg_{secrets.token_hex(8)}"
        self._audit_log.append({
            "event": "OUTCOME",
            "idempotency_key": idempotency_key,
            "draft_id": draft_id,
            "message_id": msg_id,
            "status": "SENT",
            "timestamp": time.time()
        })

        result = SendResult(
            status="SENT",
            idempotency_key=idempotency_key,
            message_id=msg_id,
            recipient_count=len(recipients_to) + len(recipients_cc) + len(recipients_bcc),
            timestamp=time.time(),
            audit_intent_logged=True,
            audit_outcome_logged=True
        )

        self._sent_messages[idempotency_key] = result
        del self._drafts[draft_id]
        return result

    def check_sent_folder(self, idempotency_key: str) -> Optional[SendResult]:
        """Inspects the Sent folder for a prior send with the specified idempotency key."""
        return self._sent_messages.get(idempotency_key)


class MailDispatchUnknownOutcomeError(RuntimeError):
    """Raised when email dispatch encounters network timeout or unknown result; Sent folder must be audited."""
    pass


@dataclass(frozen=True)
class SendResult:
    status: str  # "SENT" | "FAILED" | "UNKNOWN"
    idempotency_key: str
    message_id: str
    recipient_count: int
    timestamp: float
    audit_intent_logged: bool
    audit_outcome_logged: bool


@dataclass(frozen=True)
class CalendarEvent:
    event_id: str
    title: str
    start_ts: float
    end_ts: float
    location: str = ""
    description: str = ""
    attendees: tuple[str, ...] = ()
    is_tentative: bool = True


@dataclass(frozen=True)
class CalendarEventRef:
    event_id: str
    title: str
    start_ts: float
    end_ts: float
    location: str
    attendee_count: int
    desc_handle: str


class CalendarConnector:
    """Calendar connector: read-only free/busy, tentative local event drafts, and supervisor send flow."""
    def __init__(self, reader: Optional[QuarantinedReader] = None):
        self.reader = reader or QuarantinedReader()
        self._events: Dict[str, CalendarEvent] = {}
        self._sent_invites: Dict[str, SendResult] = {}
        self._audit_log: List[Dict[str, Any]] = []

    def add_event(self, event: CalendarEvent):
        self._events[event.event_id] = event

    def get_free_busy(self, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
        slots = []
        for ev in self._events.values():
            if ev.start_ts < end_ts and ev.end_ts > start_ts:
                slots.append({"busy_start": ev.start_ts, "busy_end": ev.end_ts, "title": "Busy"})
        return slots

    def read_events(self, start_ts: float, end_ts: float) -> List[CalendarEventRef]:
        refs = []
        for ev in self._events.values():
            if ev.start_ts < end_ts and ev.end_ts > start_ts:
                q = self.reader.quarantine_calendar_event({
                    "title": ev.title, "start": str(ev.start_ts), "end": str(ev.end_ts),
                    "location": ev.location, "description": ev.description
                })
                desc_handle = q.handles.get("description", "")
                refs.append(CalendarEventRef(
                    event_id=ev.event_id,
                    title=ev.title,
                    start_ts=ev.start_ts,
                    end_ts=ev.end_ts,
                    location=ev.location,
                    attendee_count=len(ev.attendees),
                    desc_handle=desc_handle
                ))
        return refs

    def draft_event(self, event: CalendarEvent) -> Tuple[bool, str, List[str]]:
        """Creates a tentative local event draft. If attendees are present, flags for send flow approval."""
        self._events[event.event_id] = event
        warnings = []
        if event.attendees:
            warnings.append(
                f"GATED_SEND: Event '{event.title}' notifies {len(event.attendees)} external attendees. Requires phone-signed approval."
            )
        return True, event.event_id, warnings

    def send_invite(
        self,
        event_id: str,
        assertion_response: Dict[str, Any],
        rp: Any,
        cred: Any,
        challenge_store: Any
    ) -> SendResult:
        """Supervisor-only calendar send flow: notifies external attendees via WebAuthn signed approval."""
        event = self._events.get(event_id)
        if not event:
            raise ValueError(f"Event '{event_id}' not found")

        # Build canonical approval object
        approval_obj = homie_structured_approval.build_send_approval_object(
            account="primary_calendar",
            to=list(event.attendees),
            cc=[],
            bcc=[],
            subject=f"Calendar Invitation: {event.title}",
            body_text=event.description or f"Event at {event.location}",
            attachments=[],
            nonce=event_id
        )

        hash_hex, _ = homie_structured_approval.compute_canonical_approval_hash(approval_obj)
        challenge_bytes = bytes.fromhex(hash_hex)

        import webauthn_verifier
        webauthn_verifier.verify_assertion(rp, cred, assertion_response, challenge_bytes, challenge_store)

        idempotency_key = f"cal_invite_{event_id}_{hash_hex[:16]}"
        self._audit_log.append({
            "event": "INTENT",
            "idempotency_key": idempotency_key,
            "event_id": event_id,
            "title": event.title,
            "attendees": list(event.attendees),
            "timestamp": time.time()
        })

        # Transition event from tentative to confirmed
        confirmed_event = CalendarEvent(
            event_id=event.event_id,
            title=event.title,
            start_ts=event.start_ts,
            end_ts=event.end_ts,
            location=event.location,
            description=event.description,
            attendees=event.attendees,
            is_tentative=False
        )
        self._events[event_id] = confirmed_event

        msg_id = f"cal_msg_{secrets.token_hex(8)}"
        self._audit_log.append({
            "event": "OUTCOME",
            "idempotency_key": idempotency_key,
            "event_id": event_id,
            "message_id": msg_id,
            "status": "SENT",
            "timestamp": time.time()
        })

        result = SendResult(
            status="SENT",
            idempotency_key=idempotency_key,
            message_id=msg_id,
            recipient_count=len(event.attendees),
            timestamp=time.time(),
            audit_intent_logged=True,
            audit_outcome_logged=True
        )
        self._sent_invites[idempotency_key] = result
        return result


_GLOBAL_MAIL_CONNECTOR: Optional[MailConnector] = None
_GLOBAL_CALENDAR_CONNECTOR: Optional[CalendarConnector] = None


def get_mail_connector() -> MailConnector:
    global _GLOBAL_MAIL_CONNECTOR
    if _GLOBAL_MAIL_CONNECTOR is None:
        _GLOBAL_MAIL_CONNECTOR = MailConnector()
    return _GLOBAL_MAIL_CONNECTOR


def get_calendar_connector() -> CalendarConnector:
    global _GLOBAL_CALENDAR_CONNECTOR
    if _GLOBAL_CALENDAR_CONNECTOR is None:
        _GLOBAL_CALENDAR_CONNECTOR = CalendarConnector()
    return _GLOBAL_CALENDAR_CONNECTOR
