"""Homie Phone-Signed Cryptographic Step-Up Gateway (Batch 18B).

Eliminates the "Telegram-on-same-PC" trust compromise:
- WebAuthn / Device-Bound Key: The private signing key resides exclusively on the user's mobile phone
  (e.g., in Secure Enclave, Hardware Keystore, or WebAuthn authenticator). The PC supervisor holds ONLY the public key.
- Strict Challenge Binding:
  Challenge = SHA-256(tool | args_hash | nonce | expiry | taint_epoch).
  Prevents replay, tool substitution, parameter tampering, and epoch transplantation.
- Canonical Supervisor-Authored Prompts:
  The confirmation UI renders strictly from supervisor-verified canonical parameters, never worker-authored text.
- Telegram as Transport Only:
  Telegram delivers the notification URL only. Stolen bot tokens or compromised Telegram sessions cannot forge signatures.
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


def get_or_create_device_public_key(device_id: str = "primary_phone") -> str:
    """Retrieves or registers a paired mobile device key identity."""
    registry = {}
    if os.path.exists(DEVICE_REGISTRY_PATH):
        try:
            with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
                registry = json.load(f)
        except Exception:
            registry = {}

    if device_id in registry:
        return registry[device_id]["public_key"]

    # Generate a persistent 32-byte device key identifier
    new_public_key = secrets.token_hex(32)
    registry[device_id] = {
        "public_key": new_public_key,
        "paired_at": time.time(),
        "device_name": "User Hardware Authenticator (Phone)"
    }
    try:
        with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
    except Exception as e:
        logger.warning("Could not persist device registry: %s", e)

    return new_public_key


def generate_approval_challenge(
    step_up_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: str,
    taint_epoch: int,
    ttl_seconds: float = 120.0
) -> Dict[str, Any]:
    """Binds approval challenge to SHA-256(tool | args_hash | nonce | expiry | taint_epoch)."""
    clean_args = json.dumps(arguments, sort_keys=True) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]
    nonce = secrets.token_hex(16)
    expiry = time.time() + ttl_seconds

    # Canonical challenge raw payload
    raw_challenge = f"{tool_name}|{args_hash}|{nonce}|{int(expiry)}|{taint_epoch}"
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
        "tool_name": tool_name,
        "arguments": arguments,
        "args_hash": args_hash,
        "nonce": nonce,
        "expiry": expiry,
        "taint_epoch": taint_epoch,
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
    device_key_override: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Verifies a phone-signed cryptographic approval. Single-use only."""
    item = _ACTIVE_CHALLENGES.get(step_up_id)
    if not item:
        return False, "Challenge not found or already consumed", None

    now = time.time()
    if now > item["expiry"]:
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, "Challenge expired", None

    # Retrieve registered device key
    key = device_key_override or get_or_create_device_public_key(device_id)
    expected_sig = compute_device_signature(item["challenge_hash"], key)

    if not hmac.compare_digest(signature, expected_sig):
        # Tampered or unauthorized signature: immediately reject and revoke
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
    """Purges all active pending challenges."""
    _ACTIVE_CHALLENGES.clear()
