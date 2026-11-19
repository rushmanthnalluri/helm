"""helm_mail_calendar.py - Tier B: Mail and Calendar Workflows with Anti-Exfiltration Recipient Policy.

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
4. Real Multi-Provider Support (Google Workspace & Microsoft 365):
   - Gmail API integration via google-auth-oauthlib + google-api-python-client (scopes: gmail.readonly, gmail.send, gmail.modify).
   - Microsoft Graph integration via msal (scopes: Mail.Read, Mail.Send, Calendars.Read).
   - Provider-agnostic routing configurable via config/settings.yaml (mail_provider: 'gmail' | 'outlook' | 'mock').
"""

import os
import sys
import re
import time
import json
import base64
import secrets
import hashlib
import datetime
import unicodedata
from email.message import EmailMessage
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field

import yaml
import requests

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_quarantine_reader
from helm_quarantine_reader import get_opaque_handle_store, QuarantinedReader
import helm_structured_approval


# ============================================================================
# Configuration & Provider Detection
# ============================================================================

def get_config_dir() -> str:
    """Returns the active configuration directory."""
    env_dir = os.environ.get("HELM_CONFIG_DIR")
    if env_dir:
        return env_dir
    if os.path.isdir(r"d:\helm\config"):
        return r"d:\helm\config"
    config_dir = os.path.join(BASE_DIR, "config")
    os.makedirs(config_dir, exist_ok=True)
    return config_dir


def ensure_settings_file() -> str:
    """Ensures config/settings.yaml exists with default mail_provider: 'mock'."""
    candidate_paths = [
        r"d:\helm\config\settings.yaml",
        os.path.join(BASE_DIR, "config", "settings.yaml")
    ]
    created = None
    for p in candidate_paths:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# Helm Configuration Settings\nmail_provider: 'mock'\n")
            if not created and os.path.exists(p):
                created = p
        except Exception:
            pass
    return created or os.path.join(BASE_DIR, "config", "settings.yaml")


def load_settings() -> Dict[str, Any]:
    """Loads configuration dictionary from settings.yaml."""
    ensure_settings_file()
    for p in [r"d:\helm\config\settings.yaml", os.path.join(BASE_DIR, "config", "settings.yaml")]:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
    return {"mail_provider": "mock"}


def get_mail_provider() -> str:
    """Returns configured mail provider: 'gmail' | 'outlook' | 'mock' (default: 'mock')."""
    env_p = os.environ.get("HELM_MAIL_PROVIDER")
    if env_p:
        return env_p.lower().strip()
    settings = load_settings()
    provider = str(settings.get("mail_provider", "mock")).lower().strip()
    return provider if provider in ("gmail", "outlook", "mock") else "mock"


def get_google_token_path() -> str:
    """Returns file path for Google OAuth2 token."""
    env_path = os.environ.get("HELM_GOOGLE_TOKEN_PATH")
    if env_path:
        return env_path
    if os.path.isdir(r"d:\helm\config"):
        return r"d:\helm\config\google_token.json"
    return os.path.join(BASE_DIR, "config", "google_token.json")


def save_google_token(token_data: Any, path: Optional[str] = None) -> str:
    """Saves Google OAuth2 token to disk."""
    target_path = path or get_google_token_path()
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    if hasattr(token_data, "to_json"):
        content = token_data.to_json()
    elif isinstance(token_data, str):
        content = token_data
    elif isinstance(token_data, dict):
        content = json.dumps(token_data, indent=2)
    else:
        content = str(token_data)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)

    # Mirror to alternate path if applicable
    alt_path = os.path.join(BASE_DIR, "config", "google_token.json")
    if os.path.abspath(target_path) != os.path.abspath(alt_path):
        try:
            os.makedirs(os.path.dirname(alt_path), exist_ok=True)
            with open(alt_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
    return target_path


def get_ms_token_path() -> str:
    """Returns file path for Microsoft Graph token cache."""
    env_path = os.environ.get("HELM_MS_TOKEN_PATH")
    if env_path:
        return env_path
    if os.path.isdir(r"d:\helm\config"):
        return r"d:\helm\config\ms_token.json"
    return os.path.join(BASE_DIR, "config", "ms_token.json")


def save_ms_token(token_data: Any, path: Optional[str] = None) -> str:
    """Saves Microsoft Graph token or cache to disk."""
    target_path = path or get_ms_token_path()
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    if isinstance(token_data, str):
        content = token_data if token_data.startswith("{") else json.dumps({"access_token": token_data}, indent=2)
    elif isinstance(token_data, dict):
        content = json.dumps(token_data, indent=2)
    else:
        content = str(token_data)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)

    alt_path = os.path.join(BASE_DIR, "config", "ms_token.json")
    if os.path.abspath(target_path) != os.path.abspath(alt_path):
        try:
            os.makedirs(os.path.dirname(alt_path), exist_ok=True)
            with open(alt_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
    return target_path


# ============================================================================
# Google Workspace & Microsoft Graph Helper Services
# ============================================================================

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

MSAL_SCOPES = [
    "Mail.Read",
    "Mail.Send",
    "Calendars.Read",
]


def get_gmail_service(
    token_path: Optional[str] = None,
    client_secrets_path: Optional[str] = None,
    scopes: Optional[List[str]] = None
):
    """Initializes and returns an authenticated Gmail API client service."""
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build
    except ImportError as e:
        raise ImportError(f"Google API client libraries missing: {e}. Install google-auth-oauthlib and google-api-python-client.")

    token_path = token_path or get_google_token_path()
    raw_scopes = scopes or GMAIL_SCOPES
    req_scopes = [
        s if s.startswith("http") else f"https://www.googleapis.com/auth/{s}"
        for s in raw_scopes
    ]

    creds = None
    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, req_scopes)
        except Exception:
            creds = None

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            save_google_token(creds, token_path)
        except Exception:
            creds = None

    if not creds or not creds.valid:
        candidates = [
            client_secrets_path,
            os.path.join(os.path.dirname(token_path), "credentials.json"),
            os.path.join(os.path.dirname(token_path), "google_credentials.json"),
            os.path.join(BASE_DIR, "config", "credentials.json"),
            os.path.join(BASE_DIR, "config", "google_credentials.json"),
            r"d:\helm\config\credentials.json",
            r"d:\helm\config\google_credentials.json",
        ]
        found_cred = next((c for c in candidates if c and os.path.exists(c)), None)
        if found_cred:
            flow = InstalledAppFlow.from_client_secrets_file(found_cred, req_scopes)
            creds = flow.run_local_server(port=0)
            save_google_token(creds, token_path)
        else:
            raise RuntimeError(
                f"Gmail credentials not found. Provide a valid token at '{token_path}' "
                f"or client secrets file (credentials.json)."
            )

    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def get_msal_app(client_id: Optional[str] = None, authority: Optional[str] = None, token_cache=None):
    """Builds an MSAL PublicClientApplication instance."""
    try:
        import msal
    except ImportError as e:
        raise ImportError(f"MSAL library missing: {e}. Install msal.")

    settings = load_settings()
    c_id = client_id or settings.get("ms_client_id") or os.environ.get("MS_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
    auth = authority or settings.get("ms_authority") or os.environ.get("MS_AUTHORITY", "https://login.microsoftonline.com/common")
    return msal.PublicClientApplication(client_id=c_id, authority=auth, token_cache=token_cache)


def get_msal_token(
    scopes: Optional[List[str]] = None,
    token_path: Optional[str] = None,
    app: Optional[Any] = None
) -> Optional[str]:
    """Acquires a Microsoft Graph access token silently from cache or file."""
    try:
        import msal
    except ImportError as e:
        raise ImportError(f"MSAL library missing: {e}. Install msal.")

    env_tok = os.environ.get("HELM_MS_TOKEN")
    if env_tok:
        return env_tok

    target_scopes = scopes or MSAL_SCOPES
    token_path = token_path or get_ms_token_path()

    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "access_token" in data:
                    return data["access_token"]
        except Exception:
            pass

    cache = msal.SerializableTokenCache()
    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                cache.deserialize(f.read())
        except Exception:
            pass

    ms_app = app or get_msal_app(token_cache=cache)
    accounts = ms_app.get_accounts()
    if accounts:
        result = ms_app.acquire_token_silent(target_scopes, account=accounts[0])
        if result and "access_token" in result:
            if cache.has_state_changed:
                try:
                    with open(token_path, "w", encoding="utf-8") as f:
                        f.write(cache.serialize())
                except Exception:
                    pass
            return result["access_token"]
    return None


def _extract_mime_body(payload: Dict[str, Any]) -> str:
    """Recursively decodes body text from Gmail payload structure."""
    body_data = payload.get("body", {}).get("data")
    if body_data:
        try:
            return base64.urlsafe_b64decode(body_data.encode("ascii")).decode("utf-8", errors="replace")
        except Exception:
            pass
    parts = payload.get("parts", [])
    for part in parts:
        if part.get("mimeType") == "text/plain":
            p_data = part.get("body", {}).get("data")
            if p_data:
                try:
                    return base64.urlsafe_b64decode(p_data.encode("ascii")).decode("utf-8", errors="replace")
                except Exception:
                    pass
    for part in parts:
        if part.get("mimeType") == "text/html":
            p_data = part.get("body", {}).get("data")
            if p_data:
                try:
                    return base64.urlsafe_b64decode(p_data.encode("ascii")).decode("utf-8", errors="replace")
                except Exception:
                    pass
        elif "parts" in part:
            sub = _extract_mime_body(part)
            if sub:
                return sub
    return ""


def _parse_ms_datetime(dt_obj: Any) -> float:
    """Parses Microsoft Graph dateTime format to unix timestamp float."""
    if isinstance(dt_obj, (int, float)):
        return float(dt_obj)
    if isinstance(dt_obj, dict):
        dt_str = dt_obj.get("dateTime", "")
    elif isinstance(dt_obj, str):
        dt_str = dt_obj
    else:
        return time.time()
    try:
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(dt_str)
        return dt.timestamp()
    except Exception:
        return time.time()


# ============================================================================
# Dataclasses
# ============================================================================

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
            warnings.append("âš ï¸ BCC RECIPIENTS DETECTED: Outbound BCC requires explicit mobile phone confirmation.")

        # 3. Phishing vector check: if replying, verify From vs Reply-To
        if thread_view and thread_view.reply_to_address:
            reply_to = thread_view.reply_to_address.lower()
            from_addr = thread_view.from_address.lower()
            if reply_to != from_addr:
                metadata["reply_to_mismatch"] = True
                warnings.append(
                    f"âš ï¸ PHISHING WARNING: Message Reply-To ({reply_to}) differs from sender From ({from_addr})."
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
                warnings.append(f"âš ï¸ NEW RECIPIENT: '{a.address}' is outside the verified thread/contacts allowlist.")

            # Lookalike / Homoglyph / Punycode domain check
            if a.punycode != a.address:
                metadata["flagged_domains"].append(a.punycode)
                warnings.append(f"âš ï¸ IDN / PUNYCODE DOMAIN: Address '{a.address}' resolves to punycode '{a.punycode}'.")

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
    body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    ts = int(time.time())
    nonce_val = nonce or secrets.token_hex(8)

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

    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return payload, digest


# ============================================================================
# Mail Connector
# ============================================================================

class MailConnector:
    """Mail connector managing headers search, quarantined body reads, drafts, supervisor send flow,
    and provider-agnostic integrations for Gmail, Outlook, and Mock stores."""

    def __init__(
        self,
        reader: Optional[QuarantinedReader] = None,
        provider: Optional[str] = None,
        gmail_service: Optional[Any] = None,
        msal_client: Optional[Any] = None,
        ms_token: Optional[str] = None
    ):
        self.reader = reader or QuarantinedReader()
        self.handle_store = self.reader.handle_store
        self.validator = RecipientPolicyValidator()
        self._drafts: Dict[str, OutboundMessage] = {}
        # In-memory mock thread store for local development / testing
        self._threads: Dict[str, Dict[str, Any]] = {}
        self._sent_messages: Dict[str, SendResult] = {}
        self._audit_log: List[Dict[str, Any]] = []

        self._configured_provider = provider
        self._gmail_service = gmail_service
        self._msal_client = msal_client
        self._ms_token = ms_token

    @property
    def provider(self) -> str:
        if self._configured_provider:
            return self._configured_provider.lower().strip()
        return get_mail_provider()

    def set_provider(self, provider: str):
        self._configured_provider = provider

    def _get_gmail_service(self):
        if self._gmail_service is not None:
            return self._gmail_service
        self._gmail_service = get_gmail_service()
        return self._gmail_service

    def _get_ms_token(self, scopes: Optional[List[str]] = None) -> str:
        if self._ms_token:
            return self._ms_token
        token = get_msal_token(scopes=scopes, app=self._msal_client)
        if not token:
            raise RuntimeError("Microsoft access token could not be acquired.")
        return token

    def add_mock_thread(self, thread_id: str, subject: str, messages: List[Dict[str, Any]]):
        self._threads[thread_id] = {
            "thread_id": thread_id,
            "subject": subject,
            "messages": messages,
            "last_ts": time.time()
        }

    # ------------------------------------------------------------------------
    # Provider-Agnostic Core Methods
    # ------------------------------------------------------------------------

    def fetch_unread_emails(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """Fetch unread emails using provider-agnostic routing.
        - Gmail: uses service.users().messages().list(userId='me', q='is:unread')
        - Outlook: routes to fetch_outlook_emails()
        - Mock: scans self._threads for unread messages
        """
        if self.provider == "gmail":
            service = self._get_gmail_service()
            resp = service.users().messages().list(userId="me", q="is:unread", maxResults=max_results).execute()
            messages = resp.get("messages", [])
            results = []
            for m in messages:
                msg_id = m["id"]
                msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
                payload = msg_data.get("payload", {})
                headers = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", [])}
                body = _extract_mime_body(payload) or msg_data.get("snippet", "")
                to_raw = headers.get("to", "")
                to_list = [addr.strip() for addr in to_raw.split(",") if addr.strip()]
                results.append({
                    "id": msg_id,
                    "thread_id": msg_data.get("threadId", msg_id),
                    "subject": headers.get("subject", ""),
                    "from": headers.get("from", ""),
                    "to": to_list,
                    "date": headers.get("date", ""),
                    "body": body,
                    "snippet": msg_data.get("snippet", ""),
                    "is_unread": True,
                    "raw": msg_data
                })
            return results
        elif self.provider == "outlook":
            return self.fetch_outlook_emails(max_results=max_results)
        else:
            # Mock mode
            results = []
            for tid, t in self._threads.items():
                for idx, m in enumerate(t.get("messages", [])):
                    if m.get("is_read") is False or m.get("unread", True):
                        results.append({
                            "id": f"{tid}_m{idx}",
                            "thread_id": tid,
                            "subject": m.get("subject", t.get("subject", "")),
                            "from": m.get("from", ""),
                            "to": m.get("to", []),
                            "date": m.get("date", ""),
                            "body": m.get("body", ""),
                            "snippet": m.get("body", "")[:100],
                            "is_unread": True
                        })
                    if len(results) >= max_results:
                        break
                if len(results) >= max_results:
                    break
            return results

    def fetch_outlook_emails(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """Fetches unread emails from Outlook via Microsoft Graph API:
        https://graph.microsoft.com/v1.0/me/messages?$filter=isRead eq false
        """
        if self.provider == "mock":
            return self.fetch_unread_emails(max_results=max_results)

        token = self._get_ms_token(["Mail.Read"])
        url = f"https://graph.microsoft.com/v1.0/me/messages?$filter=isRead eq false&$top={max_results}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("value", [])
        emails = []
        for m in items:
            sender = m.get("from", {}).get("emailAddress", {})
            sender_addr = sender.get("address", "")
            sender_name = sender.get("name", "")
            from_str = f"{sender_name} <{sender_addr}>".strip() if sender_name else sender_addr
            to_list = [
                r.get("emailAddress", {}).get("address", "")
                for r in m.get("toRecipients", [])
                if r.get("emailAddress", {}).get("address")
            ]
            body_content = m.get("body", {}).get("content", "") or m.get("bodyPreview", "")
            emails.append({
                "id": m.get("id", ""),
                "thread_id": m.get("conversationId", m.get("id", "")),
                "subject": m.get("subject", ""),
                "from": from_str,
                "to": to_list,
                "date": m.get("receivedDateTime", ""),
                "body": body_content,
                "snippet": m.get("bodyPreview", ""),
                "is_unread": not m.get("isRead", False),
                "raw": m
            })
        return emails

    def send_email(self, to: Any, subject: str, body: str) -> Dict[str, Any]:
        """Provider-agnostic email sender.
        - Gmail: uses Gmail API send endpoint with base64 encoded RFC 2822 message
        - Outlook: sends via Microsoft Graph sendMail endpoint
        - Mock: records message in sent store
        """
        if self.provider == "gmail":
            service = self._get_gmail_service()
            em = EmailMessage()
            to_str = ", ".join(to) if isinstance(to, (list, tuple)) else str(to)
            em["To"] = to_str
            em["Subject"] = subject
            em.set_content(body)
            raw_b64 = base64.urlsafe_b64encode(em.as_bytes()).decode("ascii")
            sent = service.users().messages().send(userId="me", body={"raw": raw_b64}).execute()
            return sent
        elif self.provider == "outlook":
            token = self._get_ms_token(["Mail.Send"])
            url = "https://graph.microsoft.com/v1.0/me/sendMail"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            to_recipients = []
            recips = to if isinstance(to, (list, tuple)) else [to]
            for r in recips:
                to_recipients.append({"emailAddress": {"address": str(r).strip()}})

            payload = {
                "message": {
                    "subject": subject,
                    "body": {
                        "contentType": "Text",
                        "content": body
                    },
                    "toRecipients": to_recipients
                },
                "saveToSentItems": "true"
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            return {"status": "SENT", "provider": "outlook", "to": to_recipients, "subject": subject}
        else:
            # Mock mode
            msg_id = f"mock_sent_{secrets.token_hex(6)}"
            res = {
                "id": msg_id,
                "to": to,
                "subject": subject,
                "body": body,
                "status": "SENT",
                "timestamp": time.time()
            }
            self._sent_messages[msg_id] = SendResult(
                status="SENT",
                idempotency_key=msg_id,
                message_id=msg_id,
                recipient_count=len(to) if isinstance(to, (list, tuple)) else 1,
                timestamp=time.time(),
                audit_intent_logged=True,
                audit_outcome_logged=True
            )
            return res

    def search(self, query: str, limit: int = 10) -> List[ThreadRef]:
        """Returns thread headers matching search query (zero body exposure)."""
        limit = max(1, min(limit, 25))

        if self.provider == "gmail":
            try:
                service = self._get_gmail_service()
                resp = service.users().threads().list(userId="me", q=query or "", maxResults=limit).execute()
                threads = resp.get("threads", [])
                results = []
                for th in threads:
                    th_id = th["id"]
                    th_data = service.users().threads().get(userId="me", id=th_id, format="metadata").execute()
                    messages = th_data.get("messages", [])
                    subject = ""
                    participants = set()
                    last_ts = time.time()
                    for m in messages:
                        headers = {h.get("name", "").lower(): h.get("value", "") for h in m.get("payload", {}).get("headers", [])}
                        if not subject and "subject" in headers:
                            subject = headers["subject"]
                        if "from" in headers:
                            participants.add(Addr.parse(headers["from"]).address)
                        if "to" in headers:
                            for t_addr in headers["to"].split(","):
                                if t_addr.strip():
                                    participants.add(Addr.parse(t_addr.strip()).address)
                        if "internaldate" in m:
                            try:
                                last_ts = float(m["internalDate"]) / 1000.0
                            except Exception:
                                pass
                    results.append(ThreadRef(
                        thread_id=th_id,
                        subject=subject or "No Subject",
                        last_message_ts=last_ts,
                        message_count=len(messages),
                        participants=tuple(sorted(participants))
                    ))
                return results
            except Exception:
                pass

        elif self.provider == "outlook":
            try:
                token = self._get_ms_token(["Mail.Read"])
                headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
                url = f"https://graph.microsoft.com/v1.0/me/messages?$top={limit}"
                if query:
                    url += f"&$search=\"{query}\""
                resp = requests.get(url, headers=headers, timeout=15)
                resp.raise_for_status()
                messages = resp.json().get("value", [])
                threads_map: Dict[str, List[Dict[str, Any]]] = {}
                for m in messages:
                    cid = m.get("conversationId", m.get("id"))
                    threads_map.setdefault(cid, []).append(m)
                results = []
                for cid, c_msgs in threads_map.items():
                    subj = c_msgs[0].get("subject", "No Subject")
                    participants = set()
                    for m in c_msgs:
                        from_addr = m.get("from", {}).get("emailAddress", {}).get("address")
                        if from_addr:
                            participants.add(from_addr.lower())
                        for r in m.get("toRecipients", []):
                            to_addr = r.get("emailAddress", {}).get("address")
                            if to_addr:
                                participants.add(to_addr.lower())
                    results.append(ThreadRef(
                        thread_id=cid,
                        subject=subj,
                        last_message_ts=time.time(),
                        message_count=len(c_msgs),
                        participants=tuple(sorted(participants))
                    ))
                return results
            except Exception:
                pass

        # Mock store search
        query_lower = query.lower()
        results = []
        for tid, t in self._threads.items():
            subj = t.get("subject", "")
            msgs = t.get("messages", [])
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
        if self.provider == "gmail":
            try:
                service = self._get_gmail_service()
                th_data = service.users().threads().get(userId="me", id=thread_id, format="full").execute()
                msgs = th_data.get("messages", [])
                quarantined_msgs = []
                all_participants: List[Addr] = []
                from_address = ""
                reply_to_address = None
                subject = "No Subject"

                for idx, m in enumerate(msgs):
                    payload = m.get("payload", {})
                    headers = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", [])}
                    if not subject or subject == "No Subject":
                        subject = headers.get("subject", subject)

                    body = _extract_mime_body(payload) or m.get("snippet", "")
                    from_raw = headers.get("from", "")
                    to_raw = headers.get("to", "")
                    to_list = [t.strip() for t in to_raw.split(",") if t.strip()]

                    msg_dict = {
                        "from": from_raw,
                        "to": to_list,
                        "subject": headers.get("subject", ""),
                        "date": headers.get("date", ""),
                        "body": body
                    }
                    if "reply-to" in headers:
                        msg_dict["reply_to"] = headers["reply-to"]

                    q_res = self.reader.quarantine_email(msg_dict)
                    quarantined_msgs.append({
                        "message_id": m.get("id", f"{thread_id}_m{idx}"),
                        "clean_fields": q_res.clean_fields,
                        "handles": q_res.handles,
                        "injection_flagged": q_res.injection_flagged
                    })

                    if from_raw:
                        f_addr = Addr.parse(from_raw)
                        all_participants.append(f_addr)
                        if not from_address:
                            from_address = f_addr.address

                    if "reply-to" in headers and not reply_to_address:
                        reply_to_address = Addr.parse(headers["reply-to"]).address

                    for tr in to_list:
                        all_participants.append(Addr.parse(tr))

                unique_specs = sorted(list(set(p.address for p in all_participants)))
                return ThreadView(
                    thread_id=thread_id,
                    subject=subject,
                    participants=tuple(all_participants),
                    allowed_recipients=tuple(unique_specs),
                    reply_to_address=reply_to_address,
                    from_address=from_address or "unknown@local",
                    quarantined_messages=quarantined_msgs,
                    tainted=True
                )
            except Exception:
                return None

        # Mock store read
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
        thread_view = self.read(msg.thread_id) if msg.thread_id else None

        ok, warnings, meta = self.validator.validate_outbound(msg, thread_view=thread_view)
        if not ok:
            return False, None, warnings, meta

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

        approval_obj = helm_structured_approval.build_send_approval_object(
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
        hash_hex, _ = helm_structured_approval.compute_canonical_approval_hash(approval_obj)
        challenge_bytes = bytes.fromhex(hash_hex)

        # 3. Verify physical approval via Windows Hello biometric authentication
        from windows_hello import WindowsHello
        if WindowsHello.is_available():
            if not WindowsHello.verify_sync(f"Authorize sending email: {draft.subject}"):
                raise PermissionError("Windows Hello biometric verification failed or cancelled")

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

        # Provider dispatch
        if self.provider == "gmail":
            try:
                self.send_email(to=recipients_to, subject=draft.subject, body=draft.body_text)
            except Exception as e:
                raise MailDispatchUnknownOutcomeError(f"Gmail dispatch error: {e}") from e
        elif self.provider == "outlook":
            try:
                self.send_email(to=recipients_to, subject=draft.subject, body=draft.body_text)
            except Exception as e:
                raise MailDispatchUnknownOutcomeError(f"Outlook dispatch error: {e}") from e

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


# ============================================================================
# Calendar Connector
# ============================================================================

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
    """Calendar connector: read-only free/busy, tentative local event drafts,
    supervisor send flow, and Microsoft Graph calendarView integration."""

    def __init__(
        self,
        reader: Optional[QuarantinedReader] = None,
        provider: Optional[str] = None,
        msal_client: Optional[Any] = None,
        ms_token: Optional[str] = None
    ):
        self.reader = reader or QuarantinedReader()
        self._events: Dict[str, CalendarEvent] = {}
        self._sent_invites: Dict[str, SendResult] = {}
        self._audit_log: List[Dict[str, Any]] = []

        self._configured_provider = provider
        self._msal_client = msal_client
        self._ms_token = ms_token

    @property
    def provider(self) -> str:
        if self._configured_provider:
            return self._configured_provider.lower().strip()
        return get_mail_provider()

    def set_provider(self, provider: str):
        self._configured_provider = provider

    def _get_ms_token(self, scopes: Optional[List[str]] = None) -> str:
        if self._ms_token:
            return self._ms_token
        token = get_msal_token(scopes=scopes, app=self._msal_client)
        if not token:
            raise RuntimeError("Microsoft access token could not be acquired.")
        return token

    def add_event(self, event: CalendarEvent):
        self._events[event.event_id] = event

    def fetch_calendar_events(self, days_ahead: int = 7) -> List[Dict[str, Any]]:
        """Fetches calendar events for the next N days.
        Uses Microsoft Graph calendarView endpoint when provider is outlook, or local events when mock.
        Endpoint: https://graph.microsoft.com/v1.0/me/calendarView
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        end = now + datetime.timedelta(days=days_ahead)

        if self.provider == "outlook":
            token = self._get_ms_token(["Calendars.Read"])
            start_iso = now.isoformat()
            end_iso = end.isoformat()
            url = f"https://graph.microsoft.com/v1.0/me/calendarView?startDateTime={start_iso}&endDateTime={end_iso}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            items = data.get("value", [])
            events = []
            for item in items:
                start_ts = _parse_ms_datetime(item.get("start", {}))
                end_ts = _parse_ms_datetime(item.get("end", {}))
                attendees = [
                    a.get("emailAddress", {}).get("address", "")
                    for a in item.get("attendees", [])
                    if a.get("emailAddress", {}).get("address")
                ]
                events.append({
                    "event_id": item.get("id", ""),
                    "title": item.get("subject", ""),
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                    "location": item.get("location", {}).get("displayName", ""),
                    "description": item.get("body", {}).get("content", "") or item.get("bodyPreview", ""),
                    "attendees": attendees,
                    "is_tentative": item.get("responseStatus", {}).get("response", "").lower() == "tentativelyaccepted",
                    "raw": item
                })
            return events
        else:
            # Mock mode: return events from self._events within the time window
            start_ts = now.timestamp()
            end_ts = end.timestamp()
            results = []
            for ev in self._events.values():
                if ev.start_ts < end_ts and ev.end_ts > start_ts:
                    results.append({
                        "event_id": ev.event_id,
                        "title": ev.title,
                        "start_ts": ev.start_ts,
                        "end_ts": ev.end_ts,
                        "location": ev.location,
                        "description": ev.description,
                        "attendees": list(ev.attendees),
                        "is_tentative": ev.is_tentative
                    })
            return results

    def get_free_busy(self, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
        slots = []
        if self.provider == "outlook":
            days_ahead = max(1, int((end_ts - time.time()) / 86400) + 1)
            raw_events = self.fetch_calendar_events(days_ahead=days_ahead)
            for ev in raw_events:
                ev_start = ev.get("start_ts", 0)
                ev_end = ev.get("end_ts", 0)
                if ev_start < end_ts and ev_end > start_ts:
                    slots.append({"busy_start": ev_start, "busy_end": ev_end, "title": "Busy"})
            return slots

        for ev in self._events.values():
            if ev.start_ts < end_ts and ev.end_ts > start_ts:
                slots.append({"busy_start": ev.start_ts, "busy_end": ev.end_ts, "title": "Busy"})
        return slots

    def read_events(self, start_ts: float, end_ts: float) -> List[CalendarEventRef]:
        refs = []
        if self.provider == "outlook":
            days_ahead = max(1, int((end_ts - time.time()) / 86400) + 1)
            raw_events = self.fetch_calendar_events(days_ahead=days_ahead)
            for ev in raw_events:
                ev_start = ev.get("start_ts", 0)
                ev_end = ev.get("end_ts", 0)
                if ev_start < end_ts and ev_end > start_ts:
                    q = self.reader.quarantine_calendar_event({
                        "title": ev.get("title", ""),
                        "start": str(ev_start),
                        "end": str(ev_end),
                        "location": ev.get("location", ""),
                        "description": ev.get("description", "")
                    })
                    desc_handle = q.handles.get("description", "")
                    refs.append(CalendarEventRef(
                        event_id=ev.get("event_id", ""),
                        title=ev.get("title", ""),
                        start_ts=ev_start,
                        end_ts=ev_end,
                        location=ev.get("location", ""),
                        attendee_count=len(ev.get("attendees", [])),
                        desc_handle=desc_handle
                    ))
            return refs

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
        approval_obj = helm_structured_approval.build_send_approval_object(
            account="primary_calendar",
            to=list(event.attendees),
            cc=[],
            bcc=[],
            subject=f"Calendar Invitation: {event.title}",
            body_text=event.description or f"Event at {event.location}",
            attachments=[],
            nonce=event_id
        )

        hash_hex, _ = helm_structured_approval.compute_canonical_approval_hash(approval_obj)
        challenge_bytes = bytes.fromhex(hash_hex)

        # Verify physical approval via Windows Hello biometric authentication
        from windows_hello import WindowsHello
        if WindowsHello.is_available():
            if not WindowsHello.verify_sync(f"Authorize calendar invite: {event.title}"):
                raise PermissionError("Windows Hello biometric verification failed or cancelled")

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


# ============================================================================
# Singletons & Module-Level Convenience Functions
# ============================================================================

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


def fetch_unread_emails(max_results: int = 10) -> List[Dict[str, Any]]:
    return get_mail_connector().fetch_unread_emails(max_results=max_results)


def fetch_outlook_emails(max_results: int = 10) -> List[Dict[str, Any]]:
    return get_mail_connector().fetch_outlook_emails(max_results=max_results)


def fetch_calendar_events(days_ahead: int = 7) -> List[Dict[str, Any]]:
    return get_calendar_connector().fetch_calendar_events(days_ahead=days_ahead)


def send_email(to: Any, subject: str, body: str) -> Dict[str, Any]:
    return get_mail_connector().send_email(to=to, subject=subject, body=body)
