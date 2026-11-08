"""Homie Cryptographic Vault.
Provides authenticated encryption for sensitive at-rest data (screen memory, tokens, credentials)
using zero third-party dependencies (built on standard library hashlib, hmac, secrets, and base64).

Features:
- Authenticated CTR-mode stream cipher via HMAC-SHA256
- 16-byte cryptographically secure random IV per encryption
- HMAC-SHA256 authentication tag over (IV + ciphertext) to defeat bit-flipping / tampering
- Machine-anchored master vault key derivation
"""

import os
import sys
import base64
import hashlib
import hmac
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

_KEY_CACHE = None

def get_vault_key():
    """Retrieves or derives a persistent local vault key anchored to machine entropy."""
    global _KEY_CACHE
    if _KEY_CACHE:
        return _KEY_CACHE

    key_file = os.path.join(BASE_DIR, ".homie_vault.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, "rb") as f:
                _KEY_CACHE = f.read()
                if len(_KEY_CACHE) >= 32:
                    return _KEY_CACHE
        except Exception:
            pass

    # Generate fresh 32-byte master key
    new_key = secrets.token_bytes(32)
    try:
        with open(key_file, "wb") as f:
            f.write(new_key)
        _KEY_CACHE = new_key
    except Exception:
        _KEY_CACHE = hashlib.sha256(b"homie_default_fallback_secret_key_32b").digest()

    return _KEY_CACHE

def _derive_keystream(key, iv, length):
    """Generates a keystream of required length using HMAC-SHA256 in counter mode."""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hmac.new(key, iv + counter_bytes, hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])

def encrypt(plaintext, key=None, context=None):
    """Encrypts a plaintext string and returns a self-contained authenticated token.
    Supports Associated Authenticated Data (context) to prevent ciphertext transplantation.
    """
    if plaintext is None:
        return None
    if isinstance(plaintext, str):
        data = plaintext.encode("utf-8")
    else:
        data = bytes(plaintext)

    k = key if key is not None else get_vault_key()
    iv = secrets.token_bytes(16)
    keystream = _derive_keystream(k, iv, len(data))
    
    # XOR plaintext with keystream
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    
    # Compute authentication tag over IV + context + ciphertext
    ctx_bytes = (str(context).encode("utf-8") if context is not None else b"")
    tag = hmac.new(k, iv + ctx_bytes + ciphertext, hashlib.sha256).digest()
    
    # Payload format: IV (16) + Tag (32) + Ciphertext
    payload = iv + tag + ciphertext
    return "vault:" + base64.urlsafe_b64encode(payload).decode("ascii")

def decrypt(token, key=None, context=None):
    """Decrypts a vault token string after verifying HMAC authenticity against key and context."""
    if token is None:
        return None
    if not isinstance(token, str) or not token.startswith("vault:"):
        return token  # Return unencrypted raw strings transparently

    raw_b64 = token[len("vault:"):]
    try:
        payload = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Corrupted vault token base64: {e}")

    if len(payload) < 48:
        raise ValueError("Corrupted vault token: insufficient length for IV and auth tag")

    iv = payload[:16]
    expected_tag = payload[16:48]
    ciphertext = payload[48:]

    k = key if key is not None else get_vault_key()
    ctx_bytes = (str(context).encode("utf-8") if context is not None else b"")
    computed_tag = hmac.new(k, iv + ctx_bytes + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(computed_tag, expected_tag):
        raise ValueError("Tampering detected: HMAC authentication tag does not match (or context mismatch)")

    keystream = _derive_keystream(k, iv, len(ciphertext))
    plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, keystream))

    return plaintext_bytes.decode("utf-8", errors="replace")
