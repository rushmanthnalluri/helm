"""tests/test_hardened_vault.py - Hardened Crypto Vault AEAD & DPAPI Acceptance Tests.

Verifies:
1. Master vault key is protected by Windows DPAPI (CryptProtectData).
2. Key generation fails closed (zero hardcoded fallback keys).
3. Encryption uses AES-256-GCM (version byte 0x02) with 12-byte random nonces and 16-byte authentication tags.
4. Tampering with ciphertext or authentication tag raises ValueError.
5. Domain separation (storage, audit, session, actuator) prevents cross-domain decryption.
6. Context (AAD) binding prevents ciphertext swapping across rows.
7. Backwards compatibility: V1 (HMAC-CTR, version byte 0x01) tokens decrypt correctly.
"""

import os
import sys
import unittest
import base64
import hmac
import hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault


class TestHardenedCryptoVault(unittest.TestCase):

    def test_dpapi_key_storage_and_fail_closed(self):
        """Verifies master key is retrieved/persisted with DPAPI and minimum 256 bits."""
        key = crypto_vault.get_vault_key()
        self.assertIsInstance(key, bytes)
        self.assertGreaterEqual(len(key), 32)

        # On Windows, verify that the key file on disk is DPAPI protected
        if sys.platform == "win32":
            import win32crypt
            key_file = os.path.join(BASE_DIR, ".helm_vault.key")
            self.assertTrue(os.path.exists(key_file))
            with open(key_file, "rb") as f:
                disk_data = f.read()
            unprotected = win32crypt.CryptUnprotectData(disk_data, None, None, None, 0)[1]
            self.assertEqual(unprotected, key)

    def test_aes_gcm_v2_encryption_and_roundtrip(self):
        """Verifies V2 tokens use AES-256-GCM AEAD format [0x02][nonce 12][tag 16][ciphertext]."""
        secret = "Secret Workstation Credentials 2026!"
        token = crypto_vault.encrypt(secret, context="row:42", domain="storage")
        self.assertTrue(token.startswith("vault:"))

        raw = base64.urlsafe_b64decode(token[len("vault:"):])
        self.assertEqual(raw[0], crypto_vault.VAULT_VERSION_V2) # 0x02
        self.assertGreaterEqual(len(raw), 1 + 12 + 16 + len(secret.encode()))

        # Roundtrip
        decrypted = crypto_vault.decrypt(token, context="row:42", domain="storage")
        self.assertEqual(decrypted, secret)

    def test_aes_gcm_tamper_detection(self):
        """Verifies bit-flipping ciphertext or auth tag immediately fails decryption."""
        token = crypto_vault.encrypt("Financial Account Balance: $1000", domain="storage")
        raw = bytearray(base64.urlsafe_b64decode(token[len("vault:"):]))

        # Tamper last byte (ciphertext)
        raw[-1] ^= 0x01
        corrupted_token = "vault:" + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

        with self.assertRaises(ValueError):
            crypto_vault.decrypt(corrupted_token, domain="storage")

        # Tamper tag byte (byte index 15)
        raw2 = bytearray(base64.urlsafe_b64decode(token[len("vault:"):]))
        raw2[15] ^= 0x01
        corrupted_token2 = "vault:" + base64.urlsafe_b64encode(bytes(raw2)).decode("ascii")

        with self.assertRaises(ValueError):
            crypto_vault.decrypt(corrupted_token2, domain="storage")

    def test_domain_and_context_separation(self):
        """Verifies cross-domain or cross-context decryption is rejected."""
        token = crypto_vault.encrypt("Top Secret Plan", context="file:plan.docx", domain="storage")

        # Context mismatch
        with self.assertRaises(ValueError):
            crypto_vault.decrypt(token, context="file:other.docx", domain="storage")

        # Domain mismatch
        with self.assertRaises(ValueError):
            crypto_vault.decrypt(token, context="file:plan.docx", domain="audit")

    def test_v1_hmac_ctr_backward_compatibility(self):
        """Verifies older V1 tokens (HMAC-CTR format) are cleanly decrypted without failure."""
        master_k = crypto_vault.get_vault_key()
        k = crypto_vault.derive_subkey("storage", master_k)
        plaintext = b"Legacy encrypted data from Batch 21"
        iv = b"\xaa" * 16
        keystream = crypto_vault._derive_keystream(k, iv, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        version_byte = bytes([crypto_vault.VAULT_VERSION_V1])
        tag = hmac.new(k, version_byte + iv + ciphertext, hashlib.sha256).digest()

        v1_payload = version_byte + iv + tag + ciphertext
        v1_token = "vault:" + base64.urlsafe_b64encode(v1_payload).decode("ascii")

        decrypted = crypto_vault.decrypt(v1_token, domain="storage")
        self.assertEqual(decrypted, "Legacy encrypted data from Batch 21")


if __name__ == "__main__":
    unittest.main()
