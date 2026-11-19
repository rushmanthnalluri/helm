"""helm_structured_approval.py - Shared Canonical Structured Approval Framework.

Key Architectural Invariants:
1. Every approval is a canonical JSON object with an explicit type ('send', 'form_submit', 'plan').
2. Strings are NFC-normalized; keys are recursively sorted.
3. Strict character hygiene: Prohibits bidirectional overrides (e.g. \u202A-\u202E, \u2066-\u2069)
   and zero-width control characters (\u200B, \u200C, \u200D, \uFEFF) to prevent visual spoofing.
4. Size caps enforced on every field to prevent memory exhaustion / UI clipping DoS.
5. Hash rebuilding: The signer (phone) independently rebuilds the canonical hash from the structured
   fields, rendering every field in full, and signs the hash.
6. The Policy Supervisor builds approval objects directly from connector / broker data.
   The agent planner model NEVER authors approval text.
"""

import json
import hashlib
import secrets
import unicodedata
from typing import Dict, Any, List, Optional, Tuple, Set


ALLOWED_APPROVAL_TYPES = frozenset({"send", "form_submit", "plan"})

# Forbidden unicode codepoints: Bidi overrides & zero-width invisibles
PROHIBITED_CODEPOINTS: Set[int] = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE, RLE, PDF, LRO, RLO
    0x2066, 0x2067, 0x2068, 0x2069,          # LRI, RLI, FSI, PDI
    0x200B,                                  # Zero-Width Space
    0x200C,                                  # Zero-Width Non-Joiner
    0x200D,                                  # Zero-Width Joiner
    0xFEFF,                                  # Byte Order Mark / Zero-Width No-Break Space
    0x00AD,                                  # Soft Hyphen
}

MAX_FIELD_LEN_DEFAULT = 65_536
MAX_SHORT_FIELD_LEN = 1_024
MAX_TOTAL_PAYLOAD_BYTES = 262_144


class StructuredApprovalSecurityError(ValueError):
    """Raised when an approval object contains spoofing characters, excessive size, or invalid structure."""
    pass


def scan_for_prohibited_characters(text: str, field_name: str = "field"):
    """Scans string for bidi override or zero-width invisible characters."""
    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp in PROHIBITED_CODEPOINTS:
            raise StructuredApprovalSecurityError(
                f"Prohibited visual spoofing character detected in '{field_name}' at position {idx} "
                f"(U+{cp:04X}). Approval refused."
            )


def normalize_nfc_recursively(obj: Any, field_path: str = "") -> Any:
    """Recursively normalizes all strings to Unicode NFC and scans for forbidden codepoints."""
    if isinstance(obj, str):
        # 1. Scan for bidi / zero-width spoofing
        scan_for_prohibited_characters(obj, field_path)
        # 2. Check length cap
        if len(obj) > MAX_FIELD_LEN_DEFAULT:
            raise StructuredApprovalSecurityError(
                f"Field '{field_path}' exceeds maximum character cap ({len(obj)} > {MAX_FIELD_LEN_DEFAULT})."
            )
        # 3. NFC normalize
        return unicodedata.normalize("NFC", obj)
    elif isinstance(obj, dict):
        normalized_dict = {}
        for k in sorted(obj.keys()):
            if not isinstance(k, str):
                raise StructuredApprovalSecurityError(f"Dict key at '{field_path}' must be string.")
            scan_for_prohibited_characters(k, f"{field_path}.key:{k}")
            norm_k = unicodedata.normalize("NFC", k)
            child_path = f"{field_path}.{norm_k}" if field_path else norm_k
            normalized_dict[norm_k] = normalize_nfc_recursively(obj[k], child_path)
        return normalized_dict
    elif isinstance(obj, (list, tuple)):
        return [normalize_nfc_recursively(item, f"{field_path}[{i}]") for i, item in enumerate(obj)]
    elif isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    else:
        raise StructuredApprovalSecurityError(f"Unsupported type '{type(obj).__name__}' at '{field_path}'.")


def compute_canonical_approval_hash(approval_payload: Dict[str, Any]) -> Tuple[str, bytes]:
    """Serializes canonical JSON and computes SHA-256 hash.
    
    Returns:
        (hex_hash, canonical_bytes)
    """
    if not isinstance(approval_payload, dict):
        raise StructuredApprovalSecurityError("Approval payload must be a dictionary.")

    approval_type = approval_payload.get("approval_type")
    if approval_type not in ALLOWED_APPROVAL_TYPES:
        raise StructuredApprovalSecurityError(
            f"Invalid approval_type '{approval_type}'. Must be one of {sorted(ALLOWED_APPROVAL_TYPES)}"
        )

    # Recursively NFC-normalize and scan
    normalized = normalize_nfc_recursively(approval_payload, "root")

    # Serialize with sorted keys and no whitespace separators
    canonical_json_str = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical_bytes = canonical_json_str.encode("utf-8")

    if len(canonical_bytes) > MAX_TOTAL_PAYLOAD_BYTES:
        raise StructuredApprovalSecurityError(
            f"Canonical approval payload exceeds total byte cap ({len(canonical_bytes)} > {MAX_TOTAL_PAYLOAD_BYTES})."
        )

    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return digest, canonical_bytes


def verify_phone_hash_rebuild(fields_dict: Dict[str, Any], claimed_hash: str) -> bool:
    """Phone-side / verifier logic: reconstructs canonical hash from fields and verifies exact equality."""
    computed_hash, _ = compute_canonical_approval_hash(fields_dict)
    return computed_hash.lower() == claimed_hash.strip().lower()


def build_send_approval_object(
    account: str,
    to: List[str],
    cc: List[str],
    bcc: List[str],
    subject: str,
    body_text: str,
    attachments: List[Dict[str, str]],
    thread_id: Optional[str] = None,
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Constructs canonical 'send' approval object for Tier B mail sends."""
    return {
        "approval_type": "send",
        "account": account,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "body_text": body_text,
        "attachments": attachments,
        "thread_id": thread_id or "",
        "nonce": nonce or secrets.token_hex(16)
    }


def build_form_submit_approval_object(
    origin: str,
    action_url: str,
    method: str,
    field_names_and_values: Dict[str, str],
    button_text: str,
    parsed_total: Optional[str] = None,
    dom_snapshot_hash: str = "",
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Constructs canonical 'form_submit' approval object for Tier C browser automation."""
    return {
        "approval_type": "form_submit",
        "origin": origin,
        "action_url": action_url,
        "method": method.upper(),
        "fields": field_names_and_values,
        "button_text": button_text,
        "parsed_total": parsed_total or "",
        "dom_snapshot_hash": dom_snapshot_hash,
        "nonce": nonce or secrets.token_hex(16)
    }


def build_plan_approval_object(
    plan_id: str,
    steps_summary: List[Dict[str, Any]],
    scope_domains: List[str],
    scope_apps: List[str],
    budget_max_steps: int,
    budget_max_keystrokes: int,
    budget_max_egress_bytes: int,
    expiry_epoch: int,
    taint_epoch: int,
    declared_untrusted_reads: List[str],
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Constructs canonical 'plan' approval object for multi-step bounded envelopes."""
    return {
        "approval_type": "plan",
        "plan_id": plan_id,
        "steps": steps_summary,
        "scope": {
            "domains": sorted(scope_domains),
            "apps": sorted(scope_apps)
        },
        "budget": {
            "max_steps": budget_max_steps,
            "max_keystrokes": budget_max_keystrokes,
            "max_egress_bytes": budget_max_egress_bytes
        },
        "expiry": expiry_epoch,
        "taint_epoch": taint_epoch,
        "declared_untrusted_reads": sorted(declared_untrusted_reads),
        "nonce": nonce or secrets.token_hex(16)
    }


def verify_webauthn_transaction_approval(
    approval_obj: Dict[str, Any],
    assertion_response: Dict[str, Any],
    rp: Any,
    cred: Any,
    challenge_store: Any
) -> Any:
    """Binds structured canonical approval objects directly to WebAuthn assertion verification.
    Computes canonical approval hash, derives the 32-byte challenge, and verifies hardware proof.
    """
    import webauthn_verifier as wv
    hash_hex, canonical_bytes = compute_canonical_approval_hash(approval_obj)
    challenge_bytes = bytes.fromhex(hash_hex)
    return wv.verify_assertion(rp, cred, assertion_response, challenge_bytes, challenge_store)

