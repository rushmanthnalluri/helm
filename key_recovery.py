"""key_recovery.py - Cryptographic Backup and Disaster Recovery for Homie Vault.

Provides secure offline backup and restore for the master workstation encryption key:
- Uses PBKDF2-HMAC-SHA256 (600,000 iterations) to derive an export wrapping key from user passphrase.
- Encrypts master DPAPI vault key using AES-256-GCM authenticated encryption.
- Exports a portable armored backup envelope (.homie-backup).
- Restores securely into Windows DPAPI-protected local storage upon verified passphrase entry.
- Tamper-proof: Any alteration to the backup blob or wrong passphrase causes immediate hard denial.
"""

import os
import sys
import json
import base64
import logging
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault

logger = logging.getLogger("homie.key_recovery")

BACKUP_VERSION = 1
PBKDF2_ITERATIONS = 600_000


def export_encrypted_backup(passphrase: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
    """Exports master vault key encrypted under a user passphrase using AES-256-GCM.
    Returns (success, message_or_filepath).
    """
    clean_pass = passphrase.strip()
    if len(clean_pass) < 10:
        return False, "Passphrase must be at least 10 characters long"

    try:
        master_key = crypto_vault.get_master_key()
        salt = get_random_bytes(16)
        wrapping_key = PBKDF2(clean_pass, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

        nonce = get_random_bytes(12)
        cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(b"HOMIE_KEY_BACKUP_V1")
        ciphertext, tag = cipher.encrypt_and_digest(master_key)

        payload = {
            "version": BACKUP_VERSION,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "iterations": PBKDF2_ITERATIONS,
            "hash": "SHA256"
        }

        armored = json.dumps(payload, indent=2)
        target_path = output_path or os.path.join(BASE_DIR, "homie_vault_backup.json")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(armored)

        logger.info("Successfully exported encrypted master key backup to %s", target_path)
        return True, target_path
    except Exception as e:
        logger.error("Failed to export master key backup: %s", e)
        return False, str(e)


def restore_encrypted_backup(backup_path: str, passphrase: str) -> Tuple[bool, str]:
    """Restores master vault key from an encrypted backup envelope into Windows DPAPI storage.
    Returns (success, message).
    """
    if not os.path.exists(backup_path):
        return False, f"Backup file not found: {backup_path}"

    clean_pass = passphrase.strip()
    if not clean_pass:
        return False, "Passphrase cannot be empty"

    try:
        with open(backup_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        if payload.get("version") != BACKUP_VERSION:
            return False, f"Unsupported backup version: {payload.get('version')}"

        salt = base64.b64decode(payload["salt_b64"])
        nonce = base64.b64decode(payload["nonce_b64"])
        tag = base64.b64decode(payload["tag_b64"])
        ciphertext = base64.b64decode(payload["ciphertext_b64"])
        iterations = int(payload.get("iterations", PBKDF2_ITERATIONS))

        wrapping_key = PBKDF2(clean_pass, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
        cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(b"HOMIE_KEY_BACKUP_V1")
        
        try:
            decrypted_master_key = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            return False, "Decryption failed: Incorrect passphrase or tampered backup payload"

        if len(decrypted_master_key) != 32:
            return False, "Restored key invalid: must be exactly 32 bytes"

        # Save restored key into Windows DPAPI storage
        crypto_vault._save_master_key_dpapi(decrypted_master_key)
        crypto_vault._MASTER_KEY = decrypted_master_key
        logger.info("Master vault key successfully restored and sealed into Windows DPAPI storage")
        return True, "Master vault key successfully restored into Windows DPAPI storage"
    except Exception as e:
        logger.error("Failed to restore backup: %s", e)
        return False, f"Restore failed: {e}"
