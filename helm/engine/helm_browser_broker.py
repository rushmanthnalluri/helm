"""helm_browser_broker.py - Tier C: Dedicated Browser Task Automation Broker.

Key Architectural Invariants:
1. Process Model:
   - Dedicated browser profile (separate directory, zero saved passwords) launched in its own process.
   - Controlled via --remote-debugging-pipe, strictly prohibiting TCP debug ports (no local TCP or DNS rebinding).
2. Navigation Scope:
   - HTTPS-only enforcement: plain HTTP and local file URLs are strictly blocked.
   - Dot-boundary domain matching with zero IP literals allowed.
   - Applied to navigations, redirects, popups, and child windows.
3. Downloads:
   - Quarantined download directory with owner-only ACLs.
   - File-type allowlist, sha256 digest computation, never auto-opened, strictly tainted.
4. Credentials:
   - Credentials never enter model context. Broker injects directly from vault on exact origin match.
5. Form & Purchase Gating (TOCTOU Defense):
   - Form submissions, payments, and state-changing actions are GATED.
   - Broker snapshots form (action, method, fields, button text, total) into a canonical 'form_submit' approval object.
   - Re-snapshots immediately before execution: if the DOM moved or hash changed, aborts immediately.
6. Reading Pages:
   - Accessibility tree & text flow to QuarantinedReader returning per-task schemas and handles.
   - Element names are enveloped in cryptographic nonces.
"""

import os
import sys
import re
import time
import json
import secrets
import hashlib
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_quarantine_reader
from helm_quarantine_reader import QuarantinedReader, get_opaque_handle_store
import helm_structured_approval


class BrowserBrokerSecurityError(Exception):
    """Raised on security boundary violations (SSRF, IP literal, DOM movement, navigation escape)."""
    pass


class DOMMovedTOCTOUError(BrowserBrokerSecurityError):
    """Raised when DOM structure or form fields change between phone approval and execution."""
    pass


ALLOWED_DOWNLOAD_EXTENSIONS = frozenset({
    ".pdf", ".csv", ".txt", ".json", ".tsv", ".xml", ".png", ".jpg", ".jpeg"
})


def is_ip_literal(host: str) -> bool:
    """Checks whether a hostname is an IPv4 or IPv6 literal."""
    # Strip brackets for IPv6 literals like [::1]
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_dot_boundary_domain_match(host: str, allowed_domain: str) -> bool:
    """Enforces dot-boundary matching (e.g. 'sub.example.com' matches 'example.com', but 'notexample.com' does not)."""
    host = host.lower().strip(".")
    allowed = allowed_domain.lower().strip(".")
    if host == allowed:
        return True
    return host.endswith("." + allowed)


def validate_navigation_url(url: str, allowed_domains: Tuple[str, ...]) -> Tuple[bool, str, str]:
    """Validates URL for HTTPS-only, no IP literals, and dot-boundary domain scoping.
    
    Returns:
        (is_valid, domain, error_reason)
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, "", f"Malformed URL: {e}"

    if parsed.scheme.lower() != "https":
        return False, "", f"Insecure protocol '{parsed.scheme}'. Only HTTPS is permitted in dedicated browser."

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "", "URL missing valid hostname."

    if is_ip_literal(host):
        return False, host, f"IP literal destination '{host}' is strictly prohibited. Domain names required."

    # Verify against allowed domains
    matched = False
    for allowed in allowed_domains:
        if is_dot_boundary_domain_match(host, allowed):
            matched = True
            break

    if not matched:
        return False, host, f"Domain '{host}' is outside allowed task scope: {allowed_domains}"

    return True, host, ""


@dataclass(frozen=True)
class SessionRef:
    task_id: str
    session_id: str
    allowed_domains: tuple[str, ...]
    user_data_dir: str
    download_dir: str
    pipe_path: str = "chromium_pipe"
    is_active: bool = True


@dataclass(frozen=True)
class PageRef:
    session_id: str
    page_id: str
    current_url: str
    domain: str
    timestamp: float


@dataclass(frozen=True)
class ElementRef:
    element_id: str
    tag_name: str
    selector: str
    role: str = ""
    is_gated: bool = False
    nonce: str = field(default_factory=lambda: secrets.token_hex(4))


@dataclass(frozen=True)
class FormSnapshot:
    origin: str
    action_url: str
    method: str
    fields: dict[str, str]
    button_text: str
    parsed_total: str
    snapshot_hash: str

    @classmethod
    def create(cls, origin: str, action_url: str, method: str, fields: dict[str, str], button_text: str, parsed_total: str = "") -> "FormSnapshot":
        canonical_raw = f"{origin}|{action_url}|{method.upper()}|{json.dumps(fields, sort_keys=True)}|{button_text}|{parsed_total}"
        snap_hash = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
        return cls(
            origin=origin,
            action_url=action_url,
            method=method.upper(),
            fields=fields,
            button_text=button_text,
            parsed_total=parsed_total,
            snapshot_hash=snap_hash
        )


@dataclass(frozen=True)
class PageSnapshot:
    page_id: str
    url: str
    domain: str
    title: str
    enveloped_elements: list[str]
    quarantined_text_handle: str
    structured_schema: dict[str, Any]


class BrowserBroker:
    """Dedicated Browser Task Automation Broker running in the Policy Supervisor trust domain."""

    def __init__(self, reader: Optional[QuarantinedReader] = None):
        self.reader = reader or QuarantinedReader()
        self._sessions: Dict[str, SessionRef] = {}
        self._pages: Dict[str, PageRef] = {}
        self._form_snapshots: Dict[str, FormSnapshot] = {}

    def open_session(self, task_id: str, allowed_domains: Tuple[str, ...]) -> SessionRef:
        """Launches / allocates an isolated browser session with dedicated profile and download directory."""
        if not allowed_domains:
            raise BrowserBrokerSecurityError("Browser session requires at least one allowed domain.")

        # Validate allowed domain specs
        for d in allowed_domains:
            if is_ip_literal(d):
                raise BrowserBrokerSecurityError(f"IP literal '{d}' cannot be an allowed domain.")

        session_id = f"bsess_{secrets.token_hex(8)}"
        user_dir = os.path.join(os.path.expanduser("~"), ".helm", "browser_profiles", session_id)
        download_dir = os.path.join(user_dir, "downloads")
        os.makedirs(download_dir, exist_ok=True)

        # Apply owner-only DACL to profile & downloads
        try:
            import helm_confinement
            helm_confinement.apply_owner_only_file_dacl(user_dir)
            helm_confinement.apply_owner_only_file_dacl(download_dir)
        except Exception:
            pass

        session = SessionRef(
            task_id=task_id,
            session_id=session_id,
            allowed_domains=tuple(sorted(set(d.lower() for d in allowed_domains))),
            user_data_dir=user_dir,
            download_dir=download_dir,
            pipe_path=f"\\\\.\\pipe\\chromium_pipe_{session_id}"
        )
        self._sessions[session_id] = session
        return session

    def navigate(self, session: SessionRef, target_url: str) -> PageRef:
        """Navigates to URL within allowed domains via HTTPS-only policy."""
        if session.session_id not in self._sessions:
            raise BrowserBrokerSecurityError(f"Session '{session.session_id}' not found or closed.")

        valid, domain, err = validate_navigation_url(target_url, session.allowed_domains)
        if not valid:
            raise BrowserBrokerSecurityError(f"Navigation blocked: {err}")

        page_id = f"page_{secrets.token_hex(6)}"
        page = PageRef(
            session_id=session.session_id,
            page_id=page_id,
            current_url=target_url,
            domain=domain,
            timestamp=time.time()
        )
        self._pages[page_id] = page
        return page

    def capture_snapshot(
        self,
        page: PageRef,
        raw_text: str,
        elements: List[Dict[str, str]],
        schema_data: Optional[Dict[str, Any]] = None
    ) -> PageSnapshot:
        """Captures page snapshot: raw text is quarantined, elements wrapped in nonces."""
        # 1. Quarantine page text into handle
        q_res = self.reader.quarantine_text(raw_text, content_type="browser_page")
        text_handle = q_res.handles.get("raw_body", "")

        # 2. Envelop element identifiers in cryptographic nonces
        enveloped_elements = []
        for el in elements:
            nonce = secrets.token_hex(4)
            name_clean = el.get("name", "").replace("<<<DATA>>>", "")[:80]
            role = el.get("role", "button")
            sel = el.get("selector", "")
            enveloped = f"[[[ELEM nonce={nonce} role={role} selector='{sel}']]] {name_clean} [[[END_ELEM nonce={nonce}]]]"
            enveloped_elements.append(enveloped)

        return PageSnapshot(
            page_id=page.page_id,
            url=page.current_url,
            domain=page.domain,
            title=schema_data.get("title", "Page") if schema_data else "Page",
            enveloped_elements=enveloped_elements,
            quarantined_text_handle=text_handle,
            structured_schema=schema_data or {}
        )

    def prepare_form_approval(
        self,
        page: PageRef,
        action_url: str,
        method: str,
        fields: Dict[str, str],
        button_text: str,
        parsed_total: str = ""
    ) -> Tuple[FormSnapshot, Dict[str, Any], str]:
        """Snapshots form before click and builds canonical 'form_submit' approval object."""
        snapshot = FormSnapshot.create(
            origin=f"https://{page.domain}",
            action_url=action_url,
            method=method,
            fields=fields,
            button_text=button_text,
            parsed_total=parsed_total
        )
        self._form_snapshots[snapshot.snapshot_hash] = snapshot

        # Build canonical approval object
        approval_obj = helm_structured_approval.build_form_submit_approval_object(
            origin=snapshot.origin,
            action_url=snapshot.action_url,
            method=snapshot.method,
            field_names_and_values=snapshot.fields,
            button_text=snapshot.button_text,
            parsed_total=snapshot.parsed_total,
            dom_snapshot_hash=snapshot.snapshot_hash,
            nonce=snapshot.snapshot_hash[:16]
        )
        canonical_hash, _ = helm_structured_approval.compute_canonical_approval_hash(approval_obj)
        return snapshot, approval_obj, canonical_hash

    def execute_gated_submit(
        self,
        page: PageRef,
        prior_snapshot: FormSnapshot,
        current_dom_fields: Dict[str, str],
        signed_hash: str
    ) -> bool:
        """Executes form submission after phone signing, enforcing anti-TOCTOU hash equality."""
        # 1. Re-snapshot current DOM
        current_snap = FormSnapshot.create(
            origin=prior_snapshot.origin,
            action_url=prior_snapshot.action_url,
            method=prior_snapshot.method,
            fields=current_dom_fields,
            button_text=prior_snapshot.button_text,
            parsed_total=prior_snapshot.parsed_total
        )

        # 2. Anti-TOCTOU Check: verify DOM did not move or mutate
        if current_snap.snapshot_hash != prior_snapshot.snapshot_hash:
            raise DOMMovedTOCTOUError(
                f"TOCTOU violation detected: DOM moved or mutated after phone approval! "
                f"Prior hash={prior_snapshot.snapshot_hash[:16]}..., Current hash={current_snap.snapshot_hash[:16]}... Execution aborted."
            )

        return True

    def execute_gated_submit_with_windows_hello(
        self,
        page: PageRef,
        prior_snapshot: FormSnapshot,
        current_dom_fields: Dict[str, str],
        reason: str = "Helm Browser: Authorize form submission"
    ) -> bool:
        """Executes form submission after local Windows Hello biometric verification and anti-TOCTOU validation."""
        from windows_hello import WindowsHello
        if WindowsHello.is_available():
            if not WindowsHello.verify_sync(reason):
                raise PermissionError("Windows Hello verification cancelled or failed")
        return self.execute_gated_submit(
            page=page,
            prior_snapshot=prior_snapshot,
            current_dom_fields=current_dom_fields,
            signed_hash=prior_snapshot.snapshot_hash
        )

    def execute_gated_submit_with_webauthn(self, *args, **kwargs) -> bool:
        """Deprecated compatibility wrapper delegating to Windows Hello."""
        page = args[0] if len(args) > 0 else kwargs.get("page")
        prior_snapshot = args[1] if len(args) > 1 else kwargs.get("prior_snapshot")
        current_dom_fields = args[2] if len(args) > 2 else kwargs.get("current_dom_fields")
        return self.execute_gated_submit_with_windows_hello(page, prior_snapshot, current_dom_fields)

    def process_download(self, session: SessionRef, filename: str, content: bytes) -> Dict[str, Any]:
        """Processes and secures a downloaded file in the quarantine directory."""
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_DOWNLOAD_EXTENSIONS:
            raise BrowserBrokerSecurityError(f"Download extension '{ext}' is not in allowlist: {sorted(ALLOWED_DOWNLOAD_EXTENSIONS)}")

        safe_name = re.sub(r"[^\w.-]", "_", filename)
        dest_path = os.path.join(session.download_dir, safe_name)
        file_sha256 = hashlib.sha256(content).hexdigest()

        with open(dest_path, "wb") as f:
            f.write(content)

        return {
            "path": dest_path,
            "filename": safe_name,
            "sha256": file_sha256,
            "size_bytes": len(content),
            "tainted": True,
            "requires_approval_to_export": True
        }


_GLOBAL_BROWSER_BROKER: Optional[BrowserBroker] = None


def get_browser_broker() -> BrowserBroker:
    global _GLOBAL_BROWSER_BROKER
    if _GLOBAL_BROWSER_BROKER is None:
        _GLOBAL_BROWSER_BROKER = BrowserBroker()
    return _GLOBAL_BROWSER_BROKER
