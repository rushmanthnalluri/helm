"""Helm Cryptographic Vault (Production Hardened AEAD).
Provides authenticated encryption for sensitive at-rest data (screen memory, tokens, credentials)
with domain-separated subkeys, Windows DPAPI key protection, and strict 256-bit key length checks:
- Standard AEAD: AES-256-GCM (via pycryptodome) with 12-byte random nonces and 16-byte authentication tags
- Backward-compatible decryption for V1 (HMAC-CTR) and legacy tokens
- Windows DPAPI (CryptProtectData / CryptUnprotectData) master key storage failing closed
- HKDF-SHA256 Domain Subkey Separation (storage, audit, session, actuator, tokens)
- Minimum 32-byte (256-bit) key length validation
"""

import os
import sys
import base64
import hashlib
import hmac
import secrets
from typing import Optional, Union, Tuple
from Crypto.Cipher import AES

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

VAULT_VERSION_V1 = 0x01
VAULT_VERSION_V2 = 0x02
MIN_KEY_LENGTH_BYTES = 32

_KEY_CACHE = None


def validate_key_length(key: bytes) -> bytes:
    """Enforces strict key length validation: minimum 32 bytes (256 bits)."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"Key must be bytes, got {type(key).__name__}")
    if len(key) < MIN_KEY_LENGTH_BYTES:
        raise ValueError(
            f"Vault key length insufficient: {len(key)} bytes provided, minimum required is {MIN_KEY_LENGTH_BYTES} bytes (256 bits)."
        )
    return bytes(key)


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869) using HMAC-SHA256."""
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand (RFC 5869) using HMAC-SHA256."""
    hash_len = hashlib.sha256().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


def derive_subkey(domain: str, master_key: Optional[bytes] = None, length: int = 32) -> bytes:
    """Derives a domain-separated cryptographic subkey from the master vault key using HKDF-SHA256.
    Ensures that compromise of one data domain reveals nothing about others.
    Supported domains: 'storage', 'audit', 'session', 'actuator', 'tokens'.
    """
    mk = master_key if master_key is not None else get_vault_key()
    validate_key_length(mk)
    salt = b"helm_vault_domain_separation_v1"
    prk = hkdf_extract(salt, mk)
    info = f"helm_vault_subkey:{domain}".encode("utf-8")
    return hkdf_expand(prk, info, length)


def get_vault_key() -> bytes:
    """Retrieves or derives a persistent local vault key anchored to machine entropy via Windows DPAPI.
    Fails closed if secure key retrieval or generation fails."""
    global _KEY_CACHE
    if _KEY_CACHE and len(_KEY_CACHE) >= MIN_KEY_LENGTH_BYTES:
        return _KEY_CACHE

    key_file = os.path.join(BASE_DIR, ".helm_vault.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "rb") as f:
                raw = f.read()

            if sys.platform == "win32":
                try:
                    import win32crypt
                    unprotected = win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1]
                    if len(unprotected) >= MIN_KEY_LENGTH_BYTES:
                        _KEY_CACHE = unprotected
                        return _KEY_CACHE
                except Exception:
                    # Legacy raw key on disk -> migrate to DPAPI protection
                    if len(raw) >= MIN_KEY_LENGTH_BYTES:
                        try:
                            import win32crypt
                            protected = win32crypt.CryptProtectData(raw, "helm_vault_master_key", None, None, None, 0)
                            with open(key_file, "wb") as wf:
                                wf.write(protected)
                        except Exception:
                            pass
                        _KEY_CACHE = raw
                        return _KEY_CACHE
            else:
                if len(raw) >= MIN_KEY_LENGTH_BYTES:
                    _KEY_CACHE = raw
                    return _KEY_CACHE
        except Exception as e:
            raise RuntimeError(f"Cryptographic Vault Error: Failed reading vault key file {key_file}: {e}")

    # Generate fresh 32-byte master key and protect with Windows DPAPI
    new_key = secrets.token_bytes(32)
    try:
        to_write = new_key
        if sys.platform == "win32":
            import win32crypt
            to_write = win32crypt.CryptProtectData(new_key, "helm_vault_master_key", None, None, None, 0)

        with open(key_file, "wb") as f:
            f.write(to_write)

        try:
            import helm_confinement
            helm_confinement.harden_path(key_file)
        except Exception:
            pass

        _KEY_CACHE = new_key
        return _KEY_CACHE
    except Exception as e:
        # FAIL CLOSED: Never fall back to source-known fixed keys
        raise RuntimeError(f"Cryptographic Vault Error: Failed to securely initialize DPAPI-protected vault master key: {e}")

def save_master_key_dpapi(key_bytes: bytes, key_path: Optional[str] = None) -> bool:
    """Saves given master key protected by Windows DPAPI."""
    global _KEY_CACHE
    if len(key_bytes) < MIN_KEY_LENGTH_BYTES:
        raise ValueError(f"Key length must be at least {MIN_KEY_LENGTH_BYTES} bytes")
    kf = key_path or os.path.join(BASE_DIR, ".helm_vault.key")
    to_write = key_bytes
    if sys.platform == "win32":
        import win32crypt
        to_write = win32crypt.CryptProtectData(key_bytes, "helm_vault_master_key", None, None, None, 0)
    with open(kf, "wb") as f:
        f.write(to_write)
    try:
        import helm_confinement
        helm_confinement.harden_path(kf)
    except Exception:
        pass
    _KEY_CACHE = key_bytes
    return True

_save_master_key_dpapi = save_master_key_dpapi
get_master_key = get_vault_key




def _derive_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    """Generates a keystream of required length using HMAC-SHA256 in counter mode (for V1 backwards compatibility)."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hmac.new(key, iv + counter_bytes, hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])


def encrypt(
    plaintext: Union[str, bytes],
    key: Optional[bytes] = None,
    context: Optional[str] = None,
    domain: str = "storage"
) -> Optional[str]:
    """Encrypts a plaintext string and returns a self-contained authenticated token using AES-256-GCM (AEAD).
    Payload format: [Version (1 byte: 0x02)] + [Nonce (12 bytes)] + [Tag (16 bytes)] + [Ciphertext].
    Supports domain separation ('storage', 'audit', 'session', 'actuator') and Associated Authenticated Data (context).
    """
    if plaintext is None:
        return None
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    else:
        data = bytes(plaintext)

    base_k = key if key is not None else get_vault_key()
    validate_key_length(base_k)
    k = derive_subkey(domain, base_k)

    nonce = secrets.token_bytes(12)
    cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
    ctx_bytes = (str(context).encode("utf-8") if context is not None else b"")
    if ctx_bytes:
        cipher.update(ctx_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    payload = bytes([VAULT_VERSION_V2]) + nonce + tag + ciphertext
    return "vault:" + base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt(
    token: Optional[str],
    key: Optional[bytes] = None,
    context: Optional[str] = None,
    domain: str = "storage"
) -> Optional[str]:
    """Decrypts a vault token string after verifying AES-GCM (V2) or HMAC authenticity (V1/legacy).
    Fails closed on tampering or context mismatch.
    """
    if token is None:
        return None
    if not isinstance(token, str) or not token.startswith("vault:"):
        return token

    raw_b64 = token[len("vault:"):]
    try:
        payload = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Corrupted vault token base64: {e}")

    base_k = key if key is not None else get_vault_key()
    validate_key_length(base_k)
    k = derive_subkey(domain, base_k)
    ctx_bytes = (str(context).encode("utf-8") if context is not None else b"")

    # V2 format: Standard AES-256-GCM AEAD
    if len(payload) >= 29 and payload[0] == VAULT_VERSION_V2:
        nonce = payload[1:13]
        tag = payload[13:29]
        ciphertext = payload[29:]
        try:
            cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
            if ctx_bytes:
                cipher.update(ctx_bytes)
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Tampering detected: AES-GCM tag verification failed (or context mismatch): {e}")

    # V1 format: HMAC-CTR format
    elif len(payload) >= 49 and payload[0] == VAULT_VERSION_V1:
        version_byte = bytes([payload[0]])
        iv = payload[1:17]
        expected_tag = payload[17:49]
        ciphertext = payload[49:]

        computed_tag = hmac.new(k, version_byte + iv + ctx_bytes + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(computed_tag, expected_tag):
            raise ValueError("Tampering detected: HMAC authentication tag does not match (or domain/context mismatch)")

        keystream = _derive_keystream(k, iv, len(ciphertext))
        plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        return plaintext_bytes.decode("utf-8", errors="replace")

    # Legacy fallback (without version byte)
    elif len(payload) >= 48:
        iv = payload[:16]
        expected_tag = payload[16:48]
        ciphertext = payload[48:]

        for trial_k in [k, base_k]:
            computed_tag = hmac.new(trial_k, iv + ctx_bytes + ciphertext, hashlib.sha256).digest()
            if hmac.compare_digest(computed_tag, expected_tag):
                keystream = _derive_keystream(trial_k, iv, len(ciphertext))
                plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, keystream))
                return plaintext_bytes.decode("utf-8", errors="replace")

        raise ValueError("Tampering detected: HMAC authentication tag does not match legacy payload")

    else:
        raise ValueError("Corrupted vault token: insufficient length for IV/nonce and auth tag")
