"""tests/phone_testing_keys.py - Ephemeral Keypair Helper for Phone Gateway and Portal Testing.

Provides cryptographic testing fixtures for asymmetric Ed25519 phone authentication.
The private key is held exclusively in test memory (simulating the phone's hardware enclave).
The PC supervisor device registry is enrolled with ONLY the public key (PEM format).
"""

import os
import sys
import time
import json
import secrets
import hashlib
from typing import Dict, Any, Tuple, Optional
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import taint_tracker


def generate_test_phone_keypair() -> Tuple[ECC.EccKey, str]:
    """Generates an ephemeral Ed25519 keypair for test simulation.
    Returns (private_key_ecc, public_key_pem).
    """
    private_key = ECC.generate(curve='ed25519')
    public_pem = private_key.public_key().export_key(format='PEM')
    return private_key, public_pem


def enroll_test_device(
    device_id: str = "primary_phone",
    public_key_pem: Optional[str] = None
) -> Tuple[ECC.EccKey, str]:
    """Enrolls a simulated mobile device into the supervisor device registry.
    Returns (phone_private_key, public_key_pem).
    The private key is returned ONLY to the test harness, NEVER stored in the registry.
    """
    private_key, pub_pem = generate_test_phone_keypair()
    final_pub_pem = public_key_pem or pub_pem

    registry = phone_approval_portal._load_device_registry()
    registry[device_id] = {
        "public_key": final_pub_pem,
        "authenticator_type": "hardware_secure_enclave_ed25519",
        "paired_at": time.time(),
        "counter": 0,
        "revoked": False,
        "device_name": f"Test Hardware Phone ({device_id})"
    }
    phone_approval_portal._save_device_registry(registry)
    return private_key, final_pub_pem


def mint_test_action_approval(
    phone_private_key: ECC.EccKey,
    action_name: str,
    payload_hash: str,
    device_id: str = "primary_phone",
    ttl_seconds: float = 120.0,
    taint_epoch: Optional[int] = None,
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Simulates a phone signing an action approval using its private key.
    Constructs the canonical payload and signs it using RFC 8032 Ed25519.
    """
    now = int(time.time())
    expiry = now + int(ttl_seconds)
    epoch = taint_tracker.get_taint_epoch() if taint_epoch is None else int(taint_epoch)
    act_nonce = nonce or secrets.token_hex(16)

    raw_msg = f"ACTION_APPROVAL_V1|{device_id}|{action_name}|{payload_hash.lower()}|{act_nonce}|{expiry}|{epoch}"
    signer = eddsa.new(phone_private_key, 'rfc8032')
    signature = signer.sign(raw_msg.encode('utf-8')).hex()

    return {
        "version": 1,
        "device_id": device_id,
        "action_name": action_name,
        "payload_hash": payload_hash.lower(),
        "nonce": act_nonce,
        "expiry": expiry,
        "taint_epoch": epoch,
        "signature": signature
    }


def sign_test_challenge(phone_private_key: ECC.EccKey, challenge_hash: str) -> str:
    """Signs a challenge hash using the phone's Ed25519 private key."""
    signer = eddsa.new(phone_private_key, 'rfc8032')
    return signer.sign(challenge_hash.encode('utf-8')).hex()


def sign_enrollment_approval(
    signing_priv_key: ECC.EccKey,
    session_id: str,
    device_id: str,
    public_key_pem: str,
    expiry: int
) -> str:
    """Signs an enrollment authorization payload binding session_id, device_id, pem, and expiry."""
    msg = f"ENROLL_DEVICE_V2|{session_id}|{device_id}|{public_key_pem.strip()}|{expiry}".encode('utf-8')
    if getattr(signing_priv_key, 'curve', '').lower() == 'ed25519':
        signer = eddsa.new(signing_priv_key, 'rfc8032')
        return signer.sign(msg).hex()
    else:
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
        h = SHA256.new(msg)
        signer = DSS.new(signing_priv_key, 'fips-186-3')
        return signer.sign(h).hex()


def get_test_pairing_code(session_id: str) -> str:
    """Test-only fixture: extracts pairing code from in-memory session (keeps production module clean)."""
    with phone_approval_portal._ENROLLMENT_LOCK:
        sess = phone_approval_portal._LOCAL_ENROLLMENT_SESSIONS.get(session_id)
        return sess["pairing_code"] if sess else ""

