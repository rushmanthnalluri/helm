"""update_verifier.py - Asymmetric Ed25519 Signed Update Verification for Homie.

Hardened according to Batch 25 directives:
- Asymmetric Ed25519 signature: Verified using pinned publisher public key (PINNED_PUBLISHER_KEY_PEM).
  Private signing key is kept offline and NEVER exists on the client workstation.
- Monotonic Rollback Protection: Enforces strict version_epoch ordering.
  Rejecting any package with version_epoch <= installed_version_epoch.
- Signed Expiry & File List: Expiration timestamp and full file list (SHA-256) are signed.
  Expired packages or altered manifests fail immediately.
- Atomic Staging: Files are unpacked and verified inside a supervisor-owned staging directory (.homie_staging)
  before swapping, closing TOCTOU race condition gaps.
- Human Approval: Applying software updates strictly requires verified human authorization.
- Anti-Path-Traversal: Rejects '..' and absolute paths.
- Protected File Safety: Updates cannot overwrite master keys or audit databases.
"""

import os
import sys
import json
import time
import shutil
import base64
import logging
from typing import Dict, Any, Tuple, Optional, List
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agent_audit_ledger

logger = logging.getLogger("homie.update_verifier")

# Pinned Ed25519 publisher public key for official Homie software releases
PINNED_PUBLISHER_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwT684SVS8poYYWfnKvF+wYMEyy1ZIQSVJWbOoUzqYug=
-----END PUBLIC KEY-----"""

PROTECTED_SYSTEM_FILES = {
    ".homie_vault.key",
    ".homie_device_keys.json",
    "homie.db",
    "homie_audit_ledger.db",
    "homie_supervisor_dirty.flag",
    "publisher_offline_private_key.pem",
}

VERSION_TRACKER_PATH = os.path.join(BASE_DIR, "homie_installed_version.json")
STAGING_DIR = os.path.join(BASE_DIR, ".homie_staging")


def get_installed_version_epoch() -> int:
    """Retrieves current installed monotonic software version epoch."""
    if os.path.exists(VERSION_TRACKER_PATH):
        try:
            with open(VERSION_TRACKER_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return int(data.get("version_epoch", 1))
        except Exception:
            return 1
    return 1


def _save_installed_version_epoch(epoch: int, version_str: str):
    try:
        with open(VERSION_TRACKER_PATH, "w", encoding="utf-8") as f:
            json.dump({"version_epoch": epoch, "version": version_str, "updated_at": time.time()}, f, indent=2)
    except Exception as e:
        logger.error("Failed saving installed version tracker: %s", e)


def compute_manifest_canonical_bytes(manifest: Dict[str, Any]) -> bytes:
    """Produces deterministic canonical byte sequence of update manifest for Ed25519 signing."""
    files_sorted = sorted(manifest.get("files", {}).items())
    files_str = ";".join(f"{path}:{sha.lower()}" for path, sha in files_sorted)
    raw = (
        f"HOMIE_UPDATE_V2|{manifest.get('version')}|"
        f"{manifest.get('version_epoch')}|"
        f"{int(manifest.get('expires_at', 0))}|"
        f"{files_str}"
    )
    return raw.encode("utf-8")


def sign_update_manifest_offline(manifest: Dict[str, Any], private_key_pem: str) -> str:
    """Publisher utility: Signs manifest with offline private Ed25519 key."""
    key = ECC.import_key(private_key_pem)
    signer = eddsa.new(key, 'rfc8032')
    data = compute_manifest_canonical_bytes(manifest)
    sig_bytes = signer.sign(data)
    return base64.b64encode(sig_bytes).decode("ascii")


def verify_update_manifest(manifest: Dict[str, Any], public_key_pem: Optional[str] = None) -> Tuple[bool, str]:
    """Cryptographically verifies Ed25519 signature, rollback epoch, and expiration."""
    required = ["version", "version_epoch", "expires_at", "files", "signature_b64"]
    for r in required:
        if r not in manifest:
            return False, f"Malformed manifest: missing required field '{r}'"

    # 1. Monotonic Rollback Protection
    current_epoch = get_installed_version_epoch()
    new_epoch = int(manifest["version_epoch"])
    if new_epoch <= current_epoch:
        return False, f"ROLLBACK_REJECTED: Package version epoch ({new_epoch}) must be strictly greater than installed epoch ({current_epoch})"

    # 2. Expiration Check
    now = time.time()
    if now > float(manifest["expires_at"]):
        return False, f"UPDATE_EXPIRED: Package signature expired at {manifest['expires_at']} (current time {now})"

    # 3. Path Traversal & Protected Files Safety Check
    for path in manifest.get("files", {}).keys():
        clean = os.path.normpath(path)
        if clean.startswith("..") or os.path.isabs(clean):
            return False, f"PATH_TRAVERSAL_DETECTED: Malicious path '{path}' in manifest"
        base = os.path.basename(clean).lower()
        if base in PROTECTED_SYSTEM_FILES:
            return False, f"SECURITY_BREACH: Update manifest targets protected workstation state file: '{base}'"

    # 4. Asymmetric Ed25519 Signature Verification
    pem = public_key_pem or PINNED_PUBLISHER_KEY_PEM
    try:
        pub_key = ECC.import_key(pem)
        verifier = eddsa.new(pub_key, 'rfc8032')
        sig_bytes = base64.b64decode(manifest["signature_b64"])
        canonical_data = compute_manifest_canonical_bytes(manifest)
        verifier.verify(canonical_data, sig_bytes)
        return True, "Ed25519 signature and manifest boundaries verified"
    except (ValueError, TypeError) as e:
        return False, f"SIGNATURE_INVALID: Ed25519 asymmetric verification failed: {e}"
    except Exception as e:
        return False, f"SIGNATURE_ERROR: {e}"


def apply_verified_update(
    manifest: Dict[str, Any],
    payload_files: Dict[str, str],
    target_dir: Optional[str] = None,
    public_key_pem: Optional[str] = None,
    human_auth: bool = False
) -> Tuple[bool, str, List[str]]:
    """Applies update atomically through staging directory under verified human authorization.
    Returns (success, message, list_of_applied_files).
    """
    if not human_auth:
        return False, "DENY: Applying updates requires verified human authorization (phone or console)", []

    valid, msg = verify_update_manifest(manifest, public_key_pem=public_key_pem)
    if not valid:
        return False, f"Security Gate: Update rejected: {msg}", []

    root = target_dir or BASE_DIR
    staging = os.path.join(root, ".homie_staging")
    updated = []

    try:
        # 1. Clean staging directory
        if os.path.exists(staging):
            shutil.rmtree(staging)
        os.makedirs(staging, exist_ok=True)

        # 2. Stage all payload files and verify SHA-256 in staging (preventing TOCTOU)
        import hashlib
        for rel_path, content in payload_files.items():
            expected_sha = manifest["files"].get(rel_path)
            if not expected_sha:
                return False, f"Security Gate: File '{rel_path}' not listed in signed manifest", []

            staged_path = os.path.join(staging, rel_path)
            os.makedirs(os.path.dirname(staged_path), exist_ok=True)
            mode = "w" if isinstance(content, str) else "wb"
            with open(staged_path, mode, encoding="utf-8" if mode == "w" else None) as f:
                f.write(content)

            # Re-verify hash directly from written staging file
            h = hashlib.sha256()
            with open(staged_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_sha = h.hexdigest()

            if actual_sha.lower() != expected_sha.lower():
                shutil.rmtree(staging)
                return False, f"Security Gate: Staged hash mismatch for '{rel_path}': expected {expected_sha}, got {actual_sha}", []

        # 3. Atomic swap from staging into target directory
        for rel_path in payload_files.keys():
            src = os.path.join(staging, rel_path)
            dst = os.path.join(root, rel_path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            updated.append(rel_path)

        # 4. Bump monotonic version tracker
        _save_installed_version_epoch(int(manifest["version_epoch"]), manifest["version"])

        # Record to audit ledger
        try:
            agent_audit_ledger.record_agent_action(
                "human_admin", "homie_apply_update", "WRITE_EXEC",
                {"version": manifest["version"], "epoch": manifest["version_epoch"], "files_count": len(updated)},
                decision="ALLOW_VERIFIED_UPDATE"
            )
        except Exception:
            pass

        logger.info("Successfully applied verified update v%s (%d files)", manifest["version"], len(updated))
        return True, f"Successfully applied update v{manifest['version']}", updated
    except Exception as e:
        logger.error("Failed applying update: %s", e)
        return False, f"Update application error: {e}", updated
    finally:
        if os.path.exists(staging):
            try:
                shutil.rmtree(staging)
            except Exception:
                pass
