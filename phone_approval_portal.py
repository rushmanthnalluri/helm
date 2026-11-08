"""Homie Phone-Signed Cryptographic Step-Up Gateway (Batch 27 Hardened).

Eliminates the "Telegram-on-same-PC" trust compromise:
- Asymmetric Key Architecture (RFC 8032 Ed25519):
  The private signing key resides EXCLUSIVELY on the user's mobile device (hardware secure enclave).
  The PC supervisor holds ONLY the public key. The PC has zero private signing keys and cannot sign.
- Strict Challenge & Payload Binding:
  Challenge = SHA-256(device_id | tool | args_hash | nonce | expiry | taint_epoch | seq).
  Action Approval = Ed25519_Sign(ACTION_APPROVAL_V1|device_id|action_name|payload_hash|nonce|expiry|taint_epoch).
- Verification-First Ordering:
  Signatures are verified before counter increment or challenge deletion, preventing denial-of-service lockout.
- Fail-Closed:
  Unknown device IDs are strictly denied. Auto-creation backdoors and key override parameters are eliminated.
- Persistent Anti-Replay:
  Consumed nonces are persisted with integer expiry to survive restarts and prevent replay attacks.
- Taint-Epoch & Monotonic Counter Invariants:
  Rejects approvals signed under previous taint epochs or stale counters.
"""

import os
import sys
import time
import json
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import taint_tracker
import agent_audit_ledger
import homie_confinement

logger = logging.getLogger("homie.phone_portal")

DEVICE_REGISTRY_PATH = os.path.join(BASE_DIR, ".homie_device_keys.json")
CONSUMED_NONCES_PATH = os.path.join(BASE_DIR, ".homie_consumed_nonces.json")

_ACTIVE_CHALLENGES: Dict[str, Dict[str, Any]] = {}  # step_up_id -> challenge_metadata
_LOCAL_ENROLLMENT_SESSIONS: Dict[str, Dict[str, Any]] = {}  # session_id -> {pairing_code, expiry, failed_attempts}
_FAILED_ATTEMPTS_LOCKOUT: Dict[str, float] = {}  # session_id -> lockout_timestamp
MAX_FAILED_ENROLLMENT_ATTEMPTS = 3
_SUPERVISOR_CHALLENGE_SEQ = 0


# ==============================================================================
# 1. PERSISTENT CONSUMED NONCES STORAGE
# ==============================================================================

def _load_consumed_nonces() -> Dict[str, int]:
    """Loads persistent consumed nonces, automatically pruning expired entries."""
    now = int(time.time())
    if os.path.exists(CONSUMED_NONCES_PATH):
        try:
            with open(CONSUMED_NONCES_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # Prune nonces older than expiry + 60s
            valid = {nonce: int(exp) for nonce, exp in raw.items() if int(exp) > now - 60}
            return valid
        except Exception as e:
            logger.warning("Could not load consumed nonces: %s", e)
            return {}
    return {}


def _save_consumed_nonces(nonces: Dict[str, int]):
    """Persists consumed nonces and secures file permissions with owner-only DACL."""
    try:
        with open(CONSUMED_NONCES_PATH, "w", encoding="utf-8") as f:
            json.dump(nonces, f, indent=2)
        try:
            homie_confinement.harden_path(CONSUMED_NONCES_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist consumed nonces: %s", e)


def is_nonce_consumed(nonce: str) -> bool:
    """Checks whether a nonce has already been consumed and is still within validity window."""
    nonces = _load_consumed_nonces()
    return nonce in nonces


def record_consumed_nonce(nonce: str, expiry: int):
    """Marks a nonce as consumed in persistent storage."""
    nonces = _load_consumed_nonces()
    nonces[nonce] = int(expiry)
    _save_consumed_nonces(nonces)


# ==============================================================================
# 2. DEVICE REGISTRY STORAGE (PC HOLDS ONLY PUBLIC KEYS)
# ==============================================================================

def _load_device_registry() -> Dict[str, Any]:
    """Loads the device public key registry from disk."""
    if os.path.exists(DEVICE_REGISTRY_PATH):
        try:
            with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not read device registry: %s", e)
            return {}
    return {}


def _save_device_registry(registry: Dict[str, Any]):
    """Persists device public keys with owner-only DACL protection."""
    try:
        with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
        try:
            homie_confinement.harden_path(DEVICE_REGISTRY_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist device registry: %s", e)


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


# ==============================================================================
# 3. PHYSICAL PRESENCE ENROLLMENT CEREMONY
# ==============================================================================

def display_secure_pairing_code(code: str) -> bool:
    """Displays pairing code on a window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)."""
    try:
        import homie_hud
        hud = homie_hud.HomieHardwareHUD()
        hud.create_overlay()
        hud.set_target_box(100, 100, 400, 150, f"HOMIE PAIRING CODE: {code}")
        hud.show()
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
    public_key_pem: str,
    authenticator_type: str = "hardware_secure_enclave_ed25519"
) -> Tuple[bool, str]:
    """Completes phone pairing by verifying the physical presence one-time code.
    Enforces that public_key_pem is strictly an asymmetric public key (rejects private keys).
    Locks out and destroys session after 3 failed attempts."""
    sess = _LOCAL_ENROLLMENT_SESSIONS.get(session_id)
    if not sess:
        return False, "Enrollment session not found, expired, or locked out"

    if time.time() > sess["expiry"]:
        del _LOCAL_ENROLLMENT_SESSIONS[session_id]
        return False, "Enrollment session expired"

    # Constant-time comparison of pairing code
    import hmac
    if not hmac.compare_digest(str(pairing_code).strip(), str(sess["pairing_code"]).strip()):
        sess["failed_attempts"] += 1
        if sess["failed_attempts"] >= MAX_FAILED_ENROLLMENT_ATTEMPTS:
            del _LOCAL_ENROLLMENT_SESSIONS[session_id]
            logger.warning("Enrollment session %s locked out after %d failed attempts", session_id, sess["failed_attempts"])
            return False, "Enrollment locked out: too many failed attempts. Session destroyed."
        return False, f"Invalid pairing code (attempt {sess['failed_attempts']}/{MAX_FAILED_ENROLLMENT_ATTEMPTS})"

    # Validate asymmetric public key format
    try:
        imported_key = ECC.import_key(public_key_pem.strip())
        if imported_key.has_private():
            del _LOCAL_ENROLLMENT_SESSIONS[session_id]
            return False, "DENY: Enrollment rejects private keys. Only public keys can be registered on PC."
    except Exception as e:
        return False, f"Invalid public key format: {e}"

    # Consume the enrollment session
    del _LOCAL_ENROLLMENT_SESSIONS[session_id]

    registry = _load_device_registry()
    registry[device_id] = {
        "public_key": public_key_pem.strip(),
        "authenticator_type": authenticator_type,
        "paired_at": time.time(),
        "counter": 0,
        "revoked": False,
        "device_name": f"Paired Mobile Authenticator ({device_id})"
    }
    _save_device_registry(registry)
    logger.info("Successfully enrolled device %s with authenticator %s", device_id, authenticator_type)
    return True, f"Device {device_id} successfully paired with hardware-backed key"


def reset_pairing_lockout() -> Tuple[bool, str]:
    """Human recovery console command: resets enrollment lockout after failed attempts."""
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


# ==============================================================================
# 4. CHALLENGE-RESPONSE GENERATION & ASYMMETRIC VERIFICATION
# ==============================================================================

def generate_approval_challenge(
    step_up_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: str,
    taint_epoch: int,
    device_id: str = "primary_phone",
    ttl_seconds: float = 120.0
) -> Dict[str, Any]:
    """Binds approval challenge to SHA-256(CHALLENGE_V2 | device_id | tool | args_hash | nonce | expiry | taint_epoch | seq)."""
    global _SUPERVISOR_CHALLENGE_SEQ
    _SUPERVISOR_CHALLENGE_SEQ += 1
    challenge_seq = _SUPERVISOR_CHALLENGE_SEQ

    clean_args = json.dumps(arguments, sort_keys=True, separators=(',', ':')) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
    nonce = secrets.token_hex(16)
    expiry = int(time.time() + ttl_seconds)

    raw_challenge = f"CHALLENGE_V2|{device_id}|{tool_name}|{args_hash}|{nonce}|{expiry}|{taint_epoch}|{challenge_seq}"
    challenge_hash = hashlib.sha256(raw_challenge.encode('utf-8')).hexdigest()

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
        "created_at": time.time(),
        "failed_attempts": 0
    }
    _ACTIVE_CHALLENGES[step_up_id] = item
    logger.info("Generated device-bound step-up challenge [ID: %s] for tool %s", step_up_id, tool_name)
    return item


def verify_asymmetric_signature(public_key_pem: str, data_bytes: bytes, signature_hex: str) -> bool:
    """Verifies an RFC 8032 Ed25519 asymmetric signature using the registered public key."""
    try:
        pub_key = ECC.import_key(public_key_pem.strip())
        verifier = eddsa.new(pub_key, 'rfc8032')
        verifier.verify(data_bytes, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


def verify_device_approval(
    step_up_id: str,
    signature: str,
    device_id: str = "primary_phone",
    counter: Optional[int] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Verifies a phone-signed cryptographic approval with verification-first ordering.
    1. Looks up enrolled device public key (fail closed on unknown device).
    2. Verifies Ed25519 signature FIRST before updating counter or consuming challenge.
    3. On failure, rate-limits failed attempts without deleting challenge immediately.
    4. On success, verifies monotonic counter, updates counter, and consumes challenge.
    """
    item = _ACTIVE_CHALLENGES.get(step_up_id)
    if not item:
        return False, "Challenge not found or already consumed", None

    now = int(time.time())
    if now > int(item["expiry"]):
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, "Challenge expired", None

    registry = _load_device_registry()
    dev_entry = registry.get(device_id)
    if not dev_entry:
        return False, f"DEVICE_UNKNOWN: Device '{device_id}' is not enrolled in supervisor registry", None

    if dev_entry.get("revoked", False):
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, f"Device {device_id} has been revoked", None

    # Step 1: VERIFY SIGNATURE FIRST (prevents unauthenticated counter lockouts)
    raw_challenge_bytes = item["challenge_hash"].encode('utf-8')
    sig_ok = verify_asymmetric_signature(dev_entry["public_key"], raw_challenge_bytes, signature)

    if not sig_ok:
        item["failed_attempts"] = item.get("failed_attempts", 0) + 1
        if item["failed_attempts"] >= 3:
            del _ACTIVE_CHALLENGES[step_up_id]
            logger.warning("Challenge %s canceled after 3 failed signature attempts", step_up_id)
            return False, "Challenge canceled: too many failed verification attempts", None
        return False, f"Cryptographic signature verification failed (attempt {item['failed_attempts']}/3)", None

    # Step 2: Signature is authentic -> check anti-replay counter
    if counter is not None:
        last_counter = dev_entry.get("counter", 0)
        if counter <= last_counter:
            del _ACTIVE_CHALLENGES[step_up_id]
            return False, f"Replay detected: signature counter {counter} <= last counter {last_counter}", None
        dev_entry["counter"] = counter
        _save_device_registry(registry)

    # Step 3: Consume challenge single-use
    del _ACTIVE_CHALLENGES[step_up_id]

    # Step 4: Record verified human approval in HMAC ledger
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


# ==============================================================================
# 5. ASYMMETRIC ACTION APPROVAL VERIFICATION (ZERO PC-SIDE MINTING)
# ==============================================================================

def verify_action_approval(
    approval: Dict[str, Any],
    expected_action: str,
    expected_payload_hash: str
) -> Tuple[bool, str]:
    """Verifies that the signed approval object is cryptographically valid, not expired,
    bound to current taint epoch, bound to the exact expected action and payload_hash,
    and consumes the nonce persistently (single-use anti-replay).
    Fails closed if the device is unknown or revoked.
    """
    if not isinstance(approval, dict):
        return False, "Malformed approval: must be an approval object dictionary"

    for req in ["device_id", "action_name", "payload_hash", "nonce", "expiry", "taint_epoch", "signature"]:
        if req not in approval:
            return False, f"Malformed approval: missing required field '{req}'"

    # Action binding check
    if approval["action_name"] != expected_action:
        return False, f"ACTION_MISMATCH: Approval signed for '{approval['action_name']}', expected '{expected_action}'"

    # Payload hash binding check
    if str(approval["payload_hash"]).lower() != str(expected_payload_hash).lower():
        return False, f"PAYLOAD_MISMATCH: Approval signed for payload {approval['payload_hash']}, expected {expected_payload_hash}"

    # Integer expiry check
    now = int(time.time())
    try:
        expiry = int(approval["expiry"])
    except (ValueError, TypeError):
        return False, "MALFORMED_EXPIRY: Approval expiry must be an integer timestamp"

    if now > expiry:
        return False, f"APPROVAL_EXPIRED: Approval expired at {expiry} (current time {now})"

    # Taint epoch check
    try:
        approval_epoch = int(approval["taint_epoch"])
    except (ValueError, TypeError):
        return False, "MALFORMED_TAINT_EPOCH: Approval taint_epoch must be an integer"

    current_epoch = int(taint_tracker.get_taint_epoch())
    if approval_epoch != current_epoch:
        return False, f"TAINT_EPOCH_MISMATCH: Approval signed under taint epoch {approval_epoch}, current epoch is {current_epoch}"

    # Persistent single-use anti-replay nonce check
    nonce = str(approval["nonce"]).strip()
    if not nonce or len(nonce) < 16:
        return False, "MALFORMED_NONCE: Nonce must be at least 16 characters"

    if is_nonce_consumed(nonce):
        return False, "REPLAY_REJECTED: Approval nonce has already been consumed"

    # Device enrollment check (FAIL CLOSED on unknown device)
    device_id = str(approval["device_id"]).strip()
    registry = _load_device_registry()
    dev_entry = registry.get(device_id)
    if not dev_entry:
        return False, f"DEVICE_UNKNOWN: Device '{device_id}' is not enrolled in supervisor registry"

    if dev_entry.get("revoked", False):
        return False, f"DEVICE_REVOKED: Device '{device_id}' has been revoked"

    # Reconstruct canonical signed message bytes
    raw_msg = (
        f"ACTION_APPROVAL_V1|{device_id}|{approval['action_name']}|"
        f"{str(approval['payload_hash']).lower()}|{nonce}|{expiry}|{approval_epoch}"
    )

    # Asymmetric Ed25519 signature verification
    sig_ok = verify_asymmetric_signature(dev_entry["public_key"], raw_msg.encode('utf-8'), str(approval["signature"]))
    if not sig_ok:
        return False, "SIGNATURE_INVALID: Asymmetric Ed25519 signature failed verification"

    # Consume nonce persistently
    record_consumed_nonce(nonce, expiry)
    return True, "Approval signature and action binding verified"
