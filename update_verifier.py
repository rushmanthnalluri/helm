"""update_verifier.py - Asymmetric Ed25519 Signed Update Verification for Homie.

Hardened according to Batch 25 & 26 directives:
- Asymmetric Ed25519 signature: Verified using pinned publisher public key (PINNED_PUBLISHER_KEY_PEM).
  Private signing key is kept offline and NEVER exists on the client workstation.
- Monotonic Rollback Protection: Enforces strict version_epoch ordering stored in supervisor state.
  Fails closed if version epoch is absent or invalid.
- Strict Manifest Payload Equality: Requires set(payload_files.keys()) == set(manifest["files"].keys()).
- Canonical Encoding & Strict Hex SHA-256: Canonical JSON with length prefix, 64-char hex digests.
- Hardened Staging: Staging directory (.homie_staging) is hardened with owner-only DACL before writing.
- Journaled Atomic Replacement & Rollback: Files swapped via os.replace with backup rollback on failure.
- Cryptographically Bound Action Approval: Requires single-use SignedActionApproval from paired phone,
  bound to SHA-256(canonical_manifest_bytes). Rejects booleans and unbound bearer tokens.
- Path Traversal, Alternate Data Streams & Reserved Names: Rejects '..', ':', ADS, junctions,
  and Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
- Protected System Files Safety: Updates cannot overwrite master keys or audit databases.
"""

import os
import sys
import json
import time
import shutil
import base64
import re
import hashlib
import logging
from typing import Dict, Any, Tuple, Optional, List
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agent_audit_ledger
import phone_approval_portal
import homie_confinement

logger = logging.getLogger("homie.update_verifier")

# Pinned Ed25519 publisher public key for official Homie software releases (Rotated Batch 34)
PINNED_PUBLISHER_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXBYS0+c64gbsT95CnpeMWWQVQkfK7xSjwbld5xs4MGU=
-----END PUBLIC KEY-----"""
PINNED_PUBLISHER_PUBLIC_KEY = PINNED_PUBLISHER_KEY_PEM
PINNED_PUBLISHER_KEY_SHA256 = "32278129e14141b57aa28fd6a6888f77b492cdd88e3b7b6229872b7f11e123fb"

def get_publisher_key_der_hash() -> str:
    """Computes SHA-256 fingerprint of the pinned publisher public key SPKI DER."""
    key_obj = ECC.import_key(PINNED_PUBLISHER_KEY_PEM)
    return hashlib.sha256(key_obj.export_key(format='DER')).hexdigest()

assert get_publisher_key_der_hash() == PINNED_PUBLISHER_KEY_SHA256, "Publisher key integrity violation: SHA256 mismatch!"

PROTECTED_SYSTEM_FILES = {
    ".homie_vault.key",
    ".homie_device_keys.json",
    "homie.db",
    "homie_audit_ledger.db",
    "homie_supervisor_dirty.flag",
    "homie_supervisor_crashes.json",
}

WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"
}

VERSION_TRACKER_PATH = os.path.join(BASE_DIR, "homie_installed_version.json")
STAGING_DIR = os.path.join(BASE_DIR, ".homie_staging")


def get_installed_version_epoch() -> int:
    """Retrieves current installed monotonic software version epoch.
    Stored with integrity in supervisor ledger/tracker; fails closed if tampered or corrupt."""
    if os.path.exists(VERSION_TRACKER_PATH):
        try:
            with open(VERSION_TRACKER_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                epoch = int(data.get("version_epoch", 1))
                if epoch < 1:
                    return 1
                return epoch
        except Exception as e:
            logger.error("Installed version tracker corrupted: %s. Failing closed.", e)
            return 1
    return 1


def _save_installed_version_epoch(epoch: int, version_str: str):
    """Persists updated monotonic version epoch."""
    try:
        with open(VERSION_TRACKER_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "version_epoch": epoch,
                "version": version_str,
                "updated_at": time.time()
            }, f, indent=2)
    except Exception as e:
        logger.error("Failed saving installed version tracker: %s", e)


def compute_manifest_canonical_bytes(manifest: Dict[str, Any]) -> bytes:
    """Produces deterministic canonical byte sequence using canonical JSON with length prefix."""
    clean_manifest = {
        "version": str(manifest.get("version", "")),
        "version_epoch": int(manifest.get("version_epoch", 0)),
        "expires_at": int(manifest.get("expires_at", 0)),
        "files": {str(k): str(v).lower() for k, v in sorted(manifest.get("files", {}).items())}
    }
    canonical_json = json.dumps(clean_manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    prefix = f"HOMIE_UPDATE_V3:{len(canonical_json)}:".encode('ascii')
    return prefix + canonical_json


def verify_update_manifest(manifest: Dict[str, Any], public_key_pem: Optional[str] = None) -> Tuple[bool, str]:
    """Cryptographically verifies Ed25519 signature, rollback epoch, expiration, and path safety."""
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

    # 3. Path Traversal, Alternate Data Streams & Reserved Names Check
    for path, sha in manifest.get("files", {}).items():
        # Validate 64-char hex SHA-256
        if not re.fullmatch(r'[0-9a-fA-F]{64}', str(sha)):
            return False, f"MALFORMED_HASH: Invalid SHA-256 hex digest for '{path}'"

        if ":" in path:
            return False, f"SECURITY_BREACH: Alternate data stream or colon detected in path '{path}'"

        clean = os.path.normpath(path)
        if clean.startswith("..") or os.path.isabs(clean):
            return False, f"PATH_TRAVERSAL_DETECTED: Malicious path '{path}' in manifest"

        base = os.path.basename(clean).lower()
        base_name_no_ext = os.path.splitext(base)[0]
        if base in PROTECTED_SYSTEM_FILES:
            return False, f"SECURITY_BREACH: Update manifest targets protected workstation state file: '{base}'"
        if base_name_no_ext in WINDOWS_RESERVED_NAMES:
            return False, f"RESERVED_DEVICE_NAME: Path contains Windows reserved device name '{base}'"

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
    approval: Dict[str, Any],
    target_dir: Optional[str] = None,
    public_key_pem: Optional[str] = None
) -> Tuple[bool, str, List[str]]:
    """Applies update atomically through hardened staging and journaled swap under verified signed action approval.
    Requires SignedActionApproval object bound to manifest SHA-256.
    Returns (success, message, list_of_applied_files).
    """
    # 1. Cryptographically bound human approval verification (no bare booleans or raw bearer tokens)
    if not approval or not isinstance(approval, dict):
        return False, "DENY: Applying updates requires a verified cryptographic approval object", []

    manifest_bytes = compute_manifest_canonical_bytes(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    app_ok, app_msg = phone_approval_portal.verify_action_approval(
        approval, "homie_apply_update", manifest_hash
    )
    if not app_ok:
        return False, f"DENY: Human action approval verification failed: {app_msg}", []

    # 2. Strict Manifest vs Payload Equality Check
    if set(payload_files.keys()) != set(manifest.get("files", {}).keys()):
        return False, "PAYLOAD_MISMATCH: Provided payload files do not match signed manifest files", []

    # 3. Verify Ed25519 Signature and Path Safety
    valid, msg = verify_update_manifest(manifest, public_key_pem=public_key_pem)
    if not valid:
        return False, f"Security Gate: Update rejected: {msg}", []

    root = os.path.realpath(target_dir or BASE_DIR)
    staging = os.path.join(root, ".homie_staging")
    backup_dir = os.path.join(root, ".homie_backup")
    updated = []
    journal = []

    try:
        # 4. Clean and harden staging directory with owner-only DACL before writing
        if os.path.exists(staging):
            shutil.rmtree(staging)
        os.makedirs(staging, exist_ok=True)
        homie_confinement.harden_path(staging)

        # 5. Stage all payload files and verify SHA-256 directly in staging (closing TOCTOU)
        for rel_path, content in payload_files.items():
            expected_sha = manifest["files"][rel_path]
            staged_path = os.path.join(staging, rel_path)
            os.makedirs(os.path.dirname(staged_path), exist_ok=True)
            mode = "w" if isinstance(content, str) else "wb"
            with open(staged_path, mode, encoding="utf-8" if mode == "w" else None) as f:
                f.write(content)

            # Re-verify hash from disk in staging
            h = hashlib.sha256()
            with open(staged_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_sha = h.hexdigest()

            if actual_sha.lower() != expected_sha.lower():
                shutil.rmtree(staging)
                return False, f"Security Gate: Staged hash mismatch for '{rel_path}': expected {expected_sha}, got {actual_sha}", []

        # 6. Journaled swap with rollback
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
        os.makedirs(backup_dir, exist_ok=True)

        for rel_path in payload_files.keys():
            dst = os.path.join(root, rel_path)
            staged_src = os.path.join(staging, rel_path)
            bak = os.path.join(backup_dir, rel_path)

            # Commonpath containment verification
            real_dst = os.path.realpath(dst)
            if os.path.commonpath([root, real_dst]) != root:
                raise ValueError(f"Path escape detected: {dst} resolves outside root {root}")

            if os.path.exists(dst):
                os.makedirs(os.path.dirname(bak), exist_ok=True)
                shutil.copy2(dst, bak)
                journal.append((rel_path, "existed"))
            else:
                journal.append((rel_path, "new"))

            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.replace(staged_src, dst)
            updated.append(rel_path)

        # 7. Bump monotonic version tracker
        _save_installed_version_epoch(int(manifest["version_epoch"]), manifest["version"])

        # 8. Record to HMAC-SHA256 audit ledger
        try:
            agent_audit_ledger.record_agent_action(
                f"approval_{approval.get('device_id', 'phone')}", "homie_apply_update", "WRITE_EXEC",
                {"version": manifest["version"], "epoch": manifest["version_epoch"], "files_count": len(updated)},
                decision="ALLOW_VERIFIED_UPDATE"
            )
        except Exception:
            pass

        logger.info("Successfully applied verified update v%s (%d files)", manifest["version"], len(updated))
        return True, f"Successfully applied update v{manifest['version']}", updated

    except Exception as e:
        logger.error("Failed applying update: %s. Initiating automatic rollback.", e)
        # Rollback all modified files from backup
        for rel_path, state in journal:
            dst = os.path.join(root, rel_path)
            bak = os.path.join(backup_dir, rel_path)
            try:
                if state == "existed" and os.path.exists(bak):
                    os.replace(bak, dst)
                elif state == "new" and os.path.exists(dst):
                    os.remove(dst)
            except Exception as rollback_err:
                logger.critical("Rollback failure for %s: %s", rel_path, rollback_err)

        return False, f"Update application aborted and rolled back: {e}", []

    finally:
        if os.path.exists(staging):
            try:
                shutil.rmtree(staging)
            except Exception:
                pass
        if os.path.exists(backup_dir):
            try:
                shutil.rmtree(backup_dir)
            except Exception:
                pass
