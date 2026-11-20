"""device_registry.py - Decoupled Device Public Key Registry & Cryptographic Signature Verifier.

Houses device public key storage, consumed anti-replay nonces, and asymmetric signature verification.
Decouples cryptographic verification and registry state from UI, HUD, and mobile approval clients,
allowing PolicySupervisor to verify signed approval evidence without importing UI or gateway modules.
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Dict, Any, Optional
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_confinement

logger = logging.getLogger("helm.device_registry")

DEVICE_REGISTRY_PATH = os.path.join(BASE_DIR, ".helm_device_keys.json")
CONSUMED_NONCES_PATH = os.path.join(BASE_DIR, ".helm_consumed_nonces.json")

_REGISTRY_LOCK = threading.RLock()
_NONCE_LOCK = threading.RLock()


# ==============================================================================
# 1. ASYMMETRIC SIGNATURE VERIFICATION (Ed25519 & NIST P-256)
# ==============================================================================

def verify_asymmetric_signature(public_key_pem: str, data_bytes: bytes, signature_hex: str) -> bool:
    """Verifies an asymmetric signature (RFC 8032 Ed25519 or NIST P-256 / secp256r1 ECDSA).
    Supports both WebCrypto IEEE P1363 binary encoding (64 bytes r||s) and ASN.1 DER encoding.
    Zero-trust fail-closed verification against public key PEM.
    """
    if not public_key_pem or not data_bytes or not signature_hex:
        return False
    try:
        pub_key = ECC.import_key(public_key_pem.strip())
        sig_bytes = bytes.fromhex(signature_hex.strip())
        curve_norm = getattr(pub_key, 'curve', '').lower().replace(' ', '').replace('-', '')
        if 'ed25519' in curve_norm:
            verifier = eddsa.new(pub_key, 'rfc8032')
            verifier.verify(data_bytes, sig_bytes)
            return True
        elif any(c in curve_norm for c in ('p256', 'prime256v1', 'secp256r1', 'nistp256')):
            from Crypto.Signature import DSS
            from Crypto.Hash import SHA256
            h = SHA256.new(data_bytes)
            for enc in ('binary', 'der'):
                try:
                    verifier = DSS.new(pub_key, 'fips-186-3', encoding=enc)
                    verifier.verify(h, sig_bytes)
                    return True
                except Exception:
                    continue
            return False
        return False
    except Exception as e:
        logger.debug("Signature verification failed: %s", e)
        return False


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


def get_enrolled_devices() -> Dict[str, Any]:
    """Returns all active, non-revoked enrolled devices."""
    with _REGISTRY_LOCK:
        reg = _load_device_registry()
        return {d_id: info for d_id, info in reg.items() if not info.get("revoked", False)}


def get_primary_device_id() -> Optional[str]:
    """Returns the primary enrolled device ID, or the first active enrolled device ID."""
    devices = get_enrolled_devices()
    for d_id, info in devices.items():
        if info.get("primary", False):
            return d_id
    if devices:
        return list(devices.keys())[0]
    return None


def _save_device_registry(registry: Dict[str, Any]):
    """Persists device public keys with owner-only DACL protection."""
    try:
        with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
        try:
            helm_confinement.harden_path(DEVICE_REGISTRY_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist device registry: %s", e)


def revoke_device_key(device_id: str) -> bool:
    """Revokes a paired device key under _REGISTRY_LOCK, immediately blocking all further approvals."""
    with _REGISTRY_LOCK:
        registry = _load_device_registry()
        if device_id in registry:
            registry[device_id]["revoked"] = True
            _save_device_registry(registry)
            logger.warning("Revoked device key %s", device_id)
            return True
        return False


# ==============================================================================
# 3. PERSISTENT CONSUMED NONCES STORAGE (ANTI-REPLAY)
# ==============================================================================

def _load_consumed_nonces() -> Dict[str, int]:
    """Loads persistent consumed nonces, automatically pruning expired entries."""
    now = int(time.time())
    if os.path.exists(CONSUMED_NONCES_PATH):
        try:
            with open(CONSUMED_NONCES_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # Prune nonces only after their approval expiry + 60s has passed
            valid = {nonce: int(exp) for nonce, exp in raw.items() if int(exp) + 60 > now}
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
            helm_confinement.harden_path(CONSUMED_NONCES_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist consumed nonces: %s", e)


def is_nonce_consumed(nonce: str) -> bool:
    """Returns True if the nonce is already in the consumed nonces store."""
    if not nonce:
        return False
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        return nonce in nonces


def record_consumed_nonce(nonce: str, expiry: int):
    """Marks a nonce as consumed in persistent storage under _NONCE_LOCK."""
    if not nonce:
        return
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        nonces[nonce] = int(expiry)
        _save_consumed_nonces(nonces)


def check_and_record_consumed_nonce(nonce: str, expiry: int) -> bool:
    """Atomically checks if nonce is consumed, and if not, records it under _NONCE_LOCK.
    Returns True if nonce was fresh and recorded successfully, False if already consumed (replay).
    """
    if not nonce:
        return False
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        if nonce in nonces:
            return False
        nonces[nonce] = int(expiry)
        _save_consumed_nonces(nonces)
        return True


def clear_consumed_nonces_for_testing():
    """Test helper to clear nonces between test cases."""
    with _NONCE_LOCK:
        if os.path.exists(CONSUMED_NONCES_PATH):
            try:
                os.remove(CONSUMED_NONCES_PATH)
            except Exception:
                pass


def clear_registry_for_testing():
    """Test helper to clear enrolled device registry between test cases."""
    with _REGISTRY_LOCK:
        if os.path.exists(DEVICE_REGISTRY_PATH):
            try:
                os.remove(DEVICE_REGISTRY_PATH)
            except Exception:
                pass
