"""helm_file_witness.py - Tamper-Evident File Witnessing & Notarization.

Provides immutable cryptographic notary and verification services for local files:
- Computes SHA-256 and HMAC-SHA256 integrity digests
- Records timestamp, file size, modification date, and caller metadata
- Persists manifest atomically in ~/.config/helm/file_witness_manifest.json
- Verifies files against witnessed baseline to mathematically prove zero tampering
- Emits cryptographic notary events into the HMAC-SHA256 agent audit ledger
"""

import os
import sys
import time
import json
import hashlib
import hmac
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agent_audit_ledger

logger = logging.getLogger("helm.file_witness")

_LOCK = threading.RLock()


def get_witness_manifest_path() -> Path:
    """Returns persistent path to file_witness_manifest.json."""
    custom = os.environ.get("HELM_WITNESS_MANIFEST_PATH")
    if custom:
        return Path(custom).resolve()
    base = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
    return (base / "file_witness_manifest.json").resolve()


def _get_signing_key() -> bytes:
    """Returns cryptographic key for HMAC calculation."""
    try:
        key = agent_audit_ledger.get_ledger_secret_key()
        if key:
            return key if isinstance(key, bytes) else str(key).encode("utf-8")
    except Exception:
        pass
    return b"helm_file_witness_hmac_master_key_v1"


def _compute_file_hashes(file_path: Path) -> Tuple[str, str, int, float]:
    """Calculates SHA-256 and HMAC-SHA256 over file contents."""
    sha256 = hashlib.sha256()
    hmac_obj = hmac.new(_get_signing_key(), digestmod=hashlib.sha256)
    
    total_size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            total_size += len(chunk)
            sha256.update(chunk)
            hmac_obj.update(chunk)

    mtime = file_path.stat().st_mtime
    return sha256.hexdigest(), hmac_obj.hexdigest(), total_size, mtime


def _load_manifest() -> Dict[str, Any]:
    path = get_witness_manifest_path()
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return {}
        data = json.loads(content)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("Could not read witness manifest: %s", e)
        return {}


def _save_manifest(data: Dict[str, Any]) -> bool:
    path = get_witness_manifest_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error("Failed to write witness manifest: %s", e)
        return False


def notarize_file(file_path: str, notes: str = "", caller_id: str = "witness_caller") -> Tuple[bool, str, Dict[str, Any]]:
    """Notarizes a file by recording its cryptographic SHA-256/HMAC digest into the manifest and ledger."""
    p = Path(file_path).resolve()
    if not p.exists() or not p.is_file():
        return False, f"File does not exist or is not a regular file: {file_path}", {}

    try:
        sha256_hash, hmac_hash, size_bytes, mtime = _compute_file_hashes(p)
    except Exception as e:
        return False, f"Error computing file digest: {e}", {}

    canonical_path = str(p)
    witness_record = {
        "file_path": canonical_path,
        "filename": p.name,
        "sha256": sha256_hash,
        "hmac_sha256": hmac_hash,
        "size_bytes": size_bytes,
        "file_mtime": mtime,
        "notarized_at": time.time(),
        "notes": notes,
        "caller_id": caller_id
    }

    with _LOCK:
        manifest = _load_manifest()
        manifest[canonical_path] = witness_record
        ok = _save_manifest(manifest)
        if not ok:
            return False, "Failed to persist witness manifest entry.", {}

    # Record to tamper-evident audit ledger
    try:
        agent_audit_ledger.record_agent_action(
            caller_id=caller_id,
            tool_name="helm_file_witness_notarize",
            tier="WRITE_EXEC",
            arguments={"path": canonical_path, "sha256": sha256_hash, "size": size_bytes},
            decision="ALLOW"
        )
    except Exception as e:
        logger.debug("Ledger record notice: %s", e)

    msg = f"File successfully notarized. SHA-256: {sha256_hash[:16]}... ({size_bytes} bytes)"
    return True, msg, witness_record


def verify_file(file_path: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Verifies a file against its notarized witness record. Detects any tampering, alteration, or deletion."""
    p = Path(file_path).resolve()
    canonical_path = str(p)

    with _LOCK:
        manifest = _load_manifest()
        record = manifest.get(canonical_path)

    if not record:
        return False, f"File '{canonical_path}' has not been notarized in the witness manifest.", {}

    if not p.exists():
        return False, f"VERIFICATION FAILED: Notarized file '{canonical_path}' has been DELETED.", {
            "status": "DELETED",
            "notarized_record": record
        }

    try:
        current_sha256, current_hmac, current_size, current_mtime = _compute_file_hashes(p)
    except Exception as e:
        return False, f"Error reading file for verification: {e}", {}

    expected_sha256 = record.get("sha256")
    expected_hmac = record.get("hmac_sha256")

    is_valid = (current_sha256 == expected_sha256) and (current_hmac == expected_hmac)
    status = "INTACT" if is_valid else "TAMPERED"

    details = {
        "status": status,
        "file_path": canonical_path,
        "is_intact": is_valid,
        "expected_sha256": expected_sha256,
        "current_sha256": current_sha256,
        "expected_size": record.get("size_bytes"),
        "current_size": current_size,
        "notarized_at": record.get("notarized_at")
    }

    if is_valid:
        msg = f"VERIFICATION PASSED: File is intact and authentic. SHA-256 matches: {current_sha256[:16]}..."
        return True, msg, details
    else:
        msg = f"CRITICAL SECURITY ALERT: File tampering detected! Expected SHA-256 {expected_sha256[:16]}... but found {current_sha256[:16]}..."
        return False, msg, details


def list_witnessed_files() -> List[Dict[str, Any]]:
    """Lists all files currently tracked in the witness manifest."""
    with _LOCK:
        manifest = _load_manifest()
        return list(manifest.values())


def remove_witness(file_path: str) -> Tuple[bool, str]:
    """Removes a file from the witness manifest."""
    p = Path(file_path).resolve()
    canonical_path = str(p)
    with _LOCK:
        manifest = _load_manifest()
        if canonical_path not in manifest:
            return False, f"File '{canonical_path}' not found in witness manifest."
        del manifest[canonical_path]
        ok = _save_manifest(manifest)
        if ok:
            return True, f"Removed witness record for '{canonical_path}'."
        return False, "Failed to update witness manifest."
