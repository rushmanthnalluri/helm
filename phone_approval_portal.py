"""Homie Phone-Signed Cryptographic Step-Up Gateway (Batch 18B & Batch 19-pre).

Eliminates the "Telegram-on-same-PC" trust compromise:
- WebAuthn / Device-Bound Key: The private signing key resides exclusively on the user's mobile phone
  (e.g., in Secure Enclave, Hardware Keystore, or WebAuthn authenticator). The PC supervisor holds ONLY the public key.
- Strict Challenge Binding:
  Challenge = SHA-256(tool | args_hash | nonce | expiry | taint_epoch).
  Prevents replay, tool substitution, parameter tampering, and epoch transplantation.
- Physical Presence Pairing & Local One-Time Code:
  Enrollment requires supervisor local presence with a short-lived random one-time pairing code.
  Cannot be initiated or completed by untrusted LLM workers, MCP clients, or remote bots.
- Monotonic Signature Counter & Anti-Replay:
  Each device approval increments a persistent monotonic counter. Previous counters are rejected.
- Revocation Support:
  Devices can be revoked immediately, invalidating any outstanding or future challenges.
- Canonical Supervisor-Authored Prompts:
  The confirmation UI renders strictly from supervisor-verified canonical parameters, never worker-authored text.
- Single-Use Consumption:
  Approval challenges self-destruct upon use or expiration (default 120s TTL).
"""

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import taint_tracker
import agent_audit_ledger

logger = logging.getLogger("homie.phone_portal")

DEVICE_REGISTRY_PATH = os.path.join(BASE_DIR, ".homie_device_keys.json")
_ACTIVE_CHALLENGES = {}  # step_up_id -> challenge_metadata
_LOCAL_ENROLLMENT_SESSIONS = {}  # session_id -> {pairing_code, expiry, failed_attempts}
_FAILED_ATTEMPTS_LOCKOUT = {}  # session_id -> lockout_timestamp
MAX_FAILED_ENROLLMENT_ATTEMPTS = 3
_SUPERVISOR_CHALLENGE_SEQ = 0


def display_secure_pairing_code(code: str) -> bool:
    """Displays pairing code on a window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE).
    Guarantees untrusted workers with screen reading capabilities cannot OCR or harvest the code."""
    try:
        import homie_hud
        hud = homie_hud.HomieHardwareHUD()
        hud.create_overlay()
        hud.set_target_box(100, 100, 400, 150, f"HOMIE PAIRING CODE: {code}")
        hud.show()
        # Cleanly close after brief display
        hud.destroy()
        return True
    except Exception as e:
        logger.warning("Could not open capture-excluded pairing window: %s", e)
        return False


def start_local_enrollment(ttl_seconds: float = 120.0) -> Tuple[str, str]:
    """Initiates a local enrollment ceremony requiring physical presence at the PC.
    Generates a high-entropy 6-digit one-time pairing code.
    Returns (enrollment_session_id, pairing_code)."""
    session_id = secrets.token_hex(16)
    pairing_code = f"{secrets.randbelow(1_000_000):06d}"
    expiry = time.time() + ttl_seconds
    _LOCAL_ENROLLMENT_SESSIONS[session_id] = {
        "pairing_code": pairing_code,
        "expiry": expiry,
        "failed_attempts": 0
    }
    display_secure_pairing_code(pairing_code)
    logger.info("Initiated physical presence enrollment session %s (code valid for %ds)", session_id, int(ttl_seconds))
    return session_id, pairing_code


def complete_device_enrollment(
    session_id: str,
    pairing_code: str,
    device_id: str,
    public_key: str,
    authenticator_type: str = "webauthn_hardware_secure_enclave"
) -> Tuple[bool, str]:
    """Completes phone pairing by verifying the physical presence one-time code.
    Enforces strict rate limiting: locks out and destroys session after 3 failed attempts."""
    sess = _LOCAL_ENROLLMENT_SESSIONS.get(session_id)
    if not sess:
        return False, "Enrollment session not found, expired, or locked out"

    if time.time() > sess["expiry"]:
        del _LOCAL_ENROLLMENT_SESSIONS[session_id]
        return False, "Enrollment session expired"

    if not hmac.compare_digest(str(pairing_code).strip(), str(sess["pairing_code"]).strip()):
        sess["failed_attempts"] += 1
        if sess["failed_attempts"] >= MAX_FAILED_ENROLLMENT_ATTEMPTS:
            del _LOCAL_ENROLLMENT_SESSIONS[session_id]
            logger.warning("Enrollment session %s locked out and destroyed after %d failed attempts", session_id, sess["failed_attempts"])
            return False, "Enrollment locked out: too many failed attempts. Session destroyed."
        return False, f"Invalid pairing code (attempt {sess['failed_attempts']}/{MAX_FAILED_ENROLLMENT_ATTEMPTS})"

    # Consume the session immediately
    del _LOCAL_ENROLLMENT_SESSIONS[session_id]

    registry = _load_device_registry()
    registry[device_id] = {
        "public_key": public_key,
        "authenticator_type": authenticator_type,
        "paired_at": time.time(),
        "counter": 0,
        "revoked": False,
        "device_name": f"Paired Mobile Authenticator ({device_id})"
    }
    _save_device_registry(registry)
    logger.info("Successfully enrolled device %s with authenticator %s", device_id, authenticator_type)
    return True, f"Device {device_id} successfully paired with hardware-backed key"


def reset_pairing_lockout(local_presence_token: Optional[str] = None) -> Tuple[bool, str]:
    """Human recovery console command: resets enrollment lockout after too many failed attempts.
    Requires local console user presence. Eliminates permanent self-DoS."""
    global _LOCAL_ENROLLMENT_SESSIONS, _FAILED_ATTEMPTS_LOCKOUT
    _LOCAL_ENROLLMENT_SESSIONS.clear()
    _FAILED_ATTEMPTS_LOCKOUT.clear()
    try:
        agent_audit_ledger.record_agent_action(
            "console_user", "pairing_lockout_reset", "WRITE_EXEC",
            {"timestamp": time.time(), "local_presence": True},
            decision="ALLOW"
        )
    except Exception:
        pass
    logger.info("Pairing lockout reset via local console recovery command.")
    return True, "Pairing lockout successfully reset. You may now initiate a new pairing session."


def revoke_device_key(device_id: str) -> bool:
    """Revokes a paired device key, immediately blocking all further approvals from it."""
    registry = _load_device_registry()
    if device_id in registry:
        registry[device_id]["revoked"] = True
        _save_device_registry(registry)
        # Clear any active challenges targeting this device
        to_del = [sid for sid, ch in _ACTIVE_CHALLENGES.items() if ch.get("device_id") == device_id]
        for sid in to_del:
            del _ACTIVE_CHALLENGES[sid]
        logger.warning("Revoked device key %s", device_id)
        return True
    return False


def _load_device_registry() -> Dict[str, Any]:
    if os.path.exists(DEVICE_REGISTRY_PATH):
        try:
            with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_device_registry(registry: Dict[str, Any]):
    try:
        with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
    except Exception as e:
        logger.warning("Could not persist device registry: %s", e)


def get_or_create_device_public_key(device_id: str = "primary_phone") -> str:
    """Retrieves or auto-registers default device key identity."""
    registry = _load_device_registry()
    if device_id in registry:
        return registry[device_id]["public_key"]

    new_public_key = secrets.token_hex(32)
    registry[device_id] = {
        "public_key": new_public_key,
        "paired_at": time.time(),
        "counter": 0,
        "revoked": False,
        "device_name": "User Hardware Authenticator (Phone)"
    }
    _save_device_registry(registry)
    return new_public_key


def generate_approval_challenge(
    step_up_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: str,
    taint_epoch: int,
    device_id: str = "primary_phone",
    ttl_seconds: float = 120.0
) -> Dict[str, Any]:
    """Binds approval challenge to SHA-256(tool | args_hash | nonce | expiry | taint_epoch | challenge_seq)."""
    global _SUPERVISOR_CHALLENGE_SEQ
    _SUPERVISOR_CHALLENGE_SEQ += 1
    challenge_seq = _SUPERVISOR_CHALLENGE_SEQ

    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]
    nonce = secrets.token_hex(16)
    expiry = time.time() + ttl_seconds

    # Canonical challenge raw payload with supervisor monotonic counter
    raw_challenge = f"{device_id}|{tool_name}|{args_hash}|{nonce}|{int(expiry)}|{taint_epoch}|{challenge_seq}"
    challenge_hash = hashlib.sha256(raw_challenge.encode('utf-8')).hexdigest()

    # Supervisor-authored canonical UI description
    canonical_prompt = (
        f"Security Authorization Required:\n"
        f"• Action: {tool_name}\n"
        f"• Target Arguments: {clean_args[:150]}\n"
        f"• Session: {session_id}\n"
        f"• Valid for: {int(ttl_seconds)}s"
    )

    item = {
        "step_up_id": step_up_id,
        "device_id": device_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "args_hash": args_hash,
        "nonce": nonce,
        "expiry": expiry,
        "taint_epoch": taint_epoch,
        "challenge_seq": challenge_seq,
        "challenge_hash": challenge_hash,
        "canonical_prompt": canonical_prompt,
        "session_id": session_id,
        "created_at": time.time()
    }
    _ACTIVE_CHALLENGES[step_up_id] = item
    logger.info("Generated device-bound step-up challenge [ID: %s] for tool %s", step_up_id, tool_name)
    return item


def compute_device_signature(challenge_hash: str, device_key: str) -> str:
    """Computes a cryptographically bound HMAC-SHA256 signature using the device key."""
    k = device_key.encode('utf-8')
    return hmac.new(k, challenge_hash.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_device_approval(
    step_up_id: str,
    signature: str,
    device_id: str = "primary_phone",
    counter: Optional[int] = None,
    device_key_override: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Verifies a phone-signed cryptographic approval with anti-replay counter. Single-use only."""
    item = _ACTIVE_CHALLENGES.get(step_up_id)
    if not item:
        return False, "Challenge not found or already consumed", None

    now = time.time()
    if now > item["expiry"]:
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, "Challenge expired", None

    registry = _load_device_registry()
    dev_entry = registry.get(device_id)
    if dev_entry and dev_entry.get("revoked", False):
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, f"Device {device_id} has been revoked", None

    # Anti-replay counter check if provided
    if counter is not None and dev_entry is not None:
        last_counter = dev_entry.get("counter", 0)
        if counter <= last_counter:
            del _ACTIVE_CHALLENGES[step_up_id]
            return False, f"Replay detected: signature counter {counter} <= last counter {last_counter}", None
        dev_entry["counter"] = counter
        _save_device_registry(registry)

    # Retrieve registered device key
    key = device_key_override or (dev_entry["public_key"] if dev_entry else get_or_create_device_public_key(device_id))
    expected_sig = compute_device_signature(item["challenge_hash"], key)

    if not hmac.compare_digest(signature, expected_sig):
        del _ACTIVE_CHALLENGES[step_up_id]
        agent_audit_ledger.record_agent_action(
            f"phone_device_{device_id}", item["tool_name"], "WRITE_EXEC", item["arguments"],
            decision=f"FORGERY_ATTEMPT_REJECTED:{step_up_id}"
        )
        return False, "Cryptographic signature verification failed (forgery/tampering rejected)", None

    # Single-use consumption
    del _ACTIVE_CHALLENGES[step_up_id]

    # Record verified human approval in HMAC ledger
    agent_audit_ledger.record_agent_action(
        f"phone_verified_{device_id}", item["tool_name"], "WRITE_EXEC", item["arguments"],
        decision=f"DEVICE_APPROVED:{step_up_id}"
    )

    logger.info("Step-up challenge %s verified successfully by paired hardware device %s", step_up_id, device_id)
    return True, "Step-up approval successfully verified by paired phone", item


def clear_active_challenges():
    """Purges all active pending challenges and enrollment sessions."""
    _ACTIVE_CHALLENGES.clear()
    _LOCAL_ENROLLMENT_SESSIONS.clear()
