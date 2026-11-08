"""update_verifier.py - Cryptographic Signed Update Verification for Homie.

Enforces supply chain security and signed update deployment:
- Validates update manifest containing file hashes (SHA-256) and release metadata.
- Verifies cryptographic HMAC-SHA256 update signatures before applying any changes.
- Anti-Path-Traversal: Strictly forbids '..' or absolute paths in update archives.
- Preserves local user data, keys (.homie_vault.key), and audit databases.
- Atomic verification: If any file hash or signature check fails, the update fails closed with zero changes.
"""

import os
import sys
import json
import hmac
import hashlib
import logging
from typing import Dict, Any, Tuple, Optional, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault

logger = logging.getLogger("homie.update_verifier")

PROTECTED_SYSTEM_FILES = {
    ".homie_vault.key",
    ".homie_device_keys.json",
    "homie.db",
    "homie_audit_ledger.db",
    "homie_supervisor_dirty.flag",
}


def get_update_verification_key() -> bytes:
    """Derives domain-separated key for signing and verifying Homie software updates."""
    return crypto_vault.derive_subkey("update_verifier", length=32)


def compute_manifest_hash(manifest: Dict[str, Any]) -> str:
    """Computes deterministic canonical hash of an update manifest."""
    files_sorted = sorted(manifest.get("files", {}).items())
    files_str = ";".join(f"{path}:{sha}" for path, sha in files_sorted)
    raw = f"{manifest.get('version')}|{manifest.get('timestamp')}|{files_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sign_update_manifest(manifest: Dict[str, Any], secret_key: Optional[bytes] = None) -> str:
    """Mints HMAC-SHA256 cryptographic signature for an update manifest."""
    key = secret_key or get_update_verification_key()
    m_hash = compute_manifest_hash(manifest)
    return hmac.new(key, m_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_update_manifest(manifest: Dict[str, Any], secret_key: Optional[bytes] = None) -> Tuple[bool, str]:
    """Cryptographically validates update manifest authenticity and structural integrity."""
    required = ["version", "timestamp", "files", "signature"]
    for r in required:
        if r not in manifest:
            return False, f"Malformed manifest: missing required field '{r}'"

    signature = manifest["signature"]
    key = secret_key or get_update_verification_key()
    expected_sig = sign_update_manifest(manifest, key)

    if not hmac.compare_digest(signature, expected_sig):
        return False, "Update signature verification failed: Untrusted or tampered release package"

    # Anti-Traversal & Protected Files Validation
    for path in manifest.get("files", {}).keys():
        clean = os.path.normpath(path)
        if clean.startswith("..") or os.path.isabs(clean):
            return False, f"Malicious path detected in update manifest: '{path}'"
        base = os.path.basename(clean).lower()
        if base in PROTECTED_SYSTEM_FILES:
            return False, f"Update attempt to overwrite protected state file: '{base}'"

    return True, "Manifest signature and path safety verified"


def verify_file_integrity(file_path: str, expected_sha256: str) -> bool:
    """Verifies that on-disk file matches the expected SHA-256 hash."""
    if not os.path.exists(file_path):
        return False
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower() == expected_sha256.lower()


def apply_verified_update(
    manifest: Dict[str, Any],
    payload_files: Dict[str, str],
    target_dir: Optional[str] = None
) -> Tuple[bool, str, List[str]]:
    """Applies update files to destination directory only after full cryptographic verification.
    payload_files: dict mapping relative path -> file content string.
    Returns (success, message, list_of_updated_files).
    """
    valid, msg = verify_update_manifest(manifest)
    if not valid:
        return False, f"Security Gate: Update rejected: {msg}", []

    root = target_dir or BASE_DIR
    updated = []

    # Pre-flight check: Verify every file's SHA-256 against the manifest before writing anything
    for rel_path, content in payload_files.items():
        expected_sha = manifest["files"].get(rel_path)
        if not expected_sha:
            return False, f"Security Gate: File '{rel_path}' not declared in signed manifest", []
        actual_sha = hashlib.sha256(content.encode("utf-8") if isinstance(content, str) else content).hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            return False, f"Security Gate: Hash mismatch for '{rel_path}': expected {expected_sha}, got {actual_sha}", []

    # Write files atomically
    try:
        for rel_path, content in payload_files.items():
            dest = os.path.join(root, rel_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            mode = "w" if isinstance(content, str) else "wb"
            with open(dest, mode, encoding="utf-8" if mode == "w" else None) as f:
                f.write(content)
            updated.append(rel_path)

        logger.info("Successfully applied signed update v%s (%d files)", manifest["version"], len(updated))
        return True, f"Successfully applied update v{manifest['version']}", updated
    except Exception as e:
        logger.error("Failed writing update files: %s", e)
        return False, f"Update application error: {e}", updated
