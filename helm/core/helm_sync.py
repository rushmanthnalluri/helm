"""helm_sync.py - Priority 4: Cross-Device Memory & Fact Sync Engine for Helm.

Provides:
- Offline-first cloud/remote sync manager for durable memory facts, preferences, and custom settings.
- Provider-agnostic adapters:
    * Supabase REST endpoint (with API key, PostgREST upsert & query headers)
    * Firebase Realtime/Firestore REST endpoint (JSON document endpoints)
    * Generic Webhook / REST JSON endpoint
    * Local file bundle adapter (.helmbundle.json)
    * MockSyncAdapter for in-memory testing & simulations
- Conflict resolution: Timestamped LWW (Last-Write-Wins) with UUID deduplication.
- End-to-end local encryption (AES-256-GCM authenticated cipher with PBKDF2 key derivation)
  ensuring memory facts and user settings are never readable in plaintext on the remote endpoint.
- Sync status and management API:
    * get_sync_status()
    * trigger_sync()
    * export_backup()
    * import_backup()
- Clean, bidirectional integration with durable_memory.py.
"""

from __future__ import annotations

import abc
import base64
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid

logger = logging.getLogger("helm.sync")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Crypto support
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning("cryptography package not available; AES-256-GCM requires cryptography.")


SYNC_BUNDLE_FORMAT = "helm_bundle"
SYNC_BUNDLE_VERSION = "1.0.0"
BUNDLE_EXTENSION = ".helmbundle.json"
DEFAULT_PBKDF2_ITERATIONS = 100_000
AAD_TAG = b"HELM_SYNC_E2EE_V1"


class SyncError(Exception):
    """Base exception for all Helm Sync operations."""
    pass


class CryptoError(SyncError):
    """Raised when encryption or decryption fails."""
    pass


class AdapterError(SyncError):
    """Raised when a remote adapter encounters a network or protocol failure."""
    pass


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SyncRecord:
    """Represents a synchronized fact, preference, or setting record with LWW metadata."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = "fact"  # "fact", "preference", "setting"
    key: str = ""
    value: Any = ""
    updated_at: float = field(default_factory=time.time)
    device_id: str = ""
    deleted: bool = False
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "key": self.key,
            "value": self.value,
            "updated_at": self.updated_at,
            "device_id": self.device_id,
            "deleted": self.deleted,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncRecord":
        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            category=str(data.get("category", "fact")),
            key=str(data.get("key", "")),
            value=data.get("value", ""),
            updated_at=float(data.get("updated_at", 0.0) or time.time()),
            device_id=str(data.get("device_id", "")),
            deleted=bool(data.get("deleted", False)),
            version=int(data.get("version", 1)),
        )


# ---------------------------------------------------------------------------
# Conflict Resolution: Timestamped LWW + UUID Deduplication
# ---------------------------------------------------------------------------

def resolve_record_conflict(
    local: Optional[SyncRecord],
    incoming: SyncRecord,
) -> Tuple[SyncRecord, bool]:
    """Resolves conflicts between local and incoming records.
    Semantics:
    1. If local is None, incoming wins (has_changed = True).
    2. If local.id == incoming.id, deduplication applies (has_changed = False, local wins).
    3. If incoming.updated_at > local.updated_at, incoming wins (has_changed = True).
    4. If incoming.updated_at < local.updated_at, local wins (has_changed = False).
    5. If timestamps are identical, tie-break deterministically using (device_id, id).
    
    Returns:
        (winning_record, has_changed)
    """
    if local is None:
        return incoming, True

    # UUID deduplication: identical record already present
    if local.id == incoming.id:
        return local, False

    if incoming.updated_at > local.updated_at:
        return incoming, True
    elif incoming.updated_at < local.updated_at:
        return local, False
    else:
        # Deterministic tie-breaker
        incoming_tie = (incoming.device_id or "", incoming.id)
        local_tie = (local.device_id or "", local.id)
        if incoming_tie > local_tie:
            return incoming, True
        return local, False


# ---------------------------------------------------------------------------
# End-to-End Cryptography Engine (AES-256-GCM + PBKDF2)
# ---------------------------------------------------------------------------

class SyncCrypto:
    """Production-grade authenticated encryption engine for end-to-end sync."""

    @staticmethod
    def derive_key(passphrase: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bytes:
        if not HAS_CRYPTOGRAPHY:
            raise CryptoError("The 'cryptography' library is required for AES-256-GCM sync encryption.")
        if not passphrase:
            raise CryptoError("Sync passphrase cannot be empty.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @classmethod
    def encrypt_payload(
        cls,
        payload_data: Dict[str, Any],
        passphrase: str,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> Dict[str, Any]:
        """Encrypts payload dictionary into an authenticated AES-256-GCM envelope."""
        if not HAS_CRYPTOGRAPHY:
            raise CryptoError("The 'cryptography' library is required for sync encryption.")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls.derive_key(passphrase, salt, iterations)
        aesgcm = AESGCM(key)

        serialized = json.dumps(payload_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, serialized, AAD_TAG)

        return {
            "version": 1,
            "encrypted": True,
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "aad": base64.b64encode(AAD_TAG).decode("ascii"),
        }

    @classmethod
    def decrypt_payload(
        cls,
        envelope: Dict[str, Any],
        passphrase: str,
    ) -> Dict[str, Any]:
        """Decrypts and authenticates an AES-256-GCM envelope using the passphrase.
        Raises ValueError if key is incorrect or ciphertext/tag is corrupted.
        """
        if not HAS_CRYPTOGRAPHY:
            raise CryptoError("The 'cryptography' library is required for sync encryption.")

        if not isinstance(envelope, dict) or not envelope.get("encrypted"):
            raise ValueError("Invalid envelope: missing encrypted flag or malformed dict")

        try:
            salt = base64.b64decode(envelope["salt"])
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            iterations = int(envelope.get("iterations", DEFAULT_PBKDF2_ITERATIONS))
            aad = base64.b64decode(envelope.get("aad", base64.b64encode(AAD_TAG).decode("ascii")))
        except Exception as e:
            raise ValueError(f"Corrupted envelope fields: {e}")

        key = cls.derive_key(passphrase, salt, iterations)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError("Decryption failed: invalid passphrase or corrupted payload") from e

        try:
            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Decrypted payload is not valid JSON: {e}") from e


# ---------------------------------------------------------------------------
# Provider-Agnostic Adapters
# ---------------------------------------------------------------------------

class SyncAdapter(abc.ABC):
    """Abstract interface for remote and local storage adapters."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the adapter."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Returns True if the storage endpoint is reachable and configured."""
        pass

    @abc.abstractmethod
    def pull(self) -> Optional[Dict[str, Any]]:
        """Pulls the latest encrypted payload from the endpoint. Returns None if empty."""
        pass

    @abc.abstractmethod
    def push(self, payload: Dict[str, Any]) -> bool:
        """Pushes an encrypted payload to the endpoint. Returns True on success."""
        pass

    def test_connection(self) -> Tuple[bool, str]:
        """Validates connection to the endpoint."""
        try:
            if not self.is_available():
                return False, f"Adapter '{self.name}' is offline or not configured."
            return True, f"Adapter '{self.name}' is operational."
        except Exception as e:
            return False, str(e)


class RestSyncAdapter(SyncAdapter):
    """Provider-agnostic HTTP REST adapter supporting Supabase, Firebase, and generic webhooks."""

    def __init__(
        self,
        endpoint: str,
        provider: str = "generic",
        api_key: Optional[str] = None,
        auth_token: Optional[str] = None,
        sync_id: str = "default",
        timeout: float = 5.0,
        custom_headers: Optional[Dict[str, str]] = None,
        request_handler: Optional[Callable[[urllib.request.Request], Tuple[int, bytes]]] = None,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.provider = provider.lower()
        self.api_key = api_key or ""
        self.auth_token = auth_token or api_key or ""
        self.sync_id = sync_id
        self.timeout = timeout
        self.custom_headers = custom_headers or {}
        self.request_handler = request_handler  # Injected mock handler for testing

    @property
    def name(self) -> str:
        return f"rest-{self.provider}"

    def is_available(self) -> bool:
        return bool(self.endpoint)

    def _build_request(self, method: str, url: str, data: Optional[bytes] = None) -> urllib.request.Request:
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "Helm-SyncEngine/1.0")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        if self.provider == "supabase":
            if self.api_key:
                req.add_header("apikey", self.api_key)
            if self.auth_token:
                req.add_header("Authorization", f"Bearer {self.auth_token}")
        elif self.provider in ("firebase", "generic", "webhook"):
            if self.auth_token:
                req.add_header("Authorization", f"Bearer {self.auth_token}")

        for k, v in self.custom_headers.items():
            req.add_header(k, v)

        return req

    def _execute_http(self, req: urllib.request.Request) -> Tuple[int, bytes]:
        if self.request_handler:
            return self.request_handler(req)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status if hasattr(resp, "status") else 200
                return status, resp.read()
        except urllib.error.HTTPError as he:
            return he.code, he.read()
        except Exception as e:
            raise AdapterError(f"HTTP network request failed: {e}") from e

    def pull(self) -> Optional[Dict[str, Any]]:
        """Pulls remote state according to the configured provider."""
        if not self.is_available():
            raise AdapterError("REST adapter is not configured.")

        if self.provider == "supabase":
            query = urllib.parse.urlencode({
                "select": "*",
                "sync_id": f"eq.{self.sync_id}",
                "order": "updated_at.desc",
                "limit": "1",
            })
            url = f"{self.endpoint}?{query}"
            req = self._build_request("GET", url)
            status, body = self._execute_http(req)
            if status in (404, 204) or not body:
                return None
            if status not in (200, 201):
                raise AdapterError(f"Supabase GET failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, list) and data:
                row = data[0]
                payload = row.get("payload") or row.get("encrypted_payload")
                return payload if isinstance(payload, dict) else row
            elif isinstance(data, dict):
                return data.get("payload") or data.get("encrypted_payload") or data
            return None

        elif self.provider == "firebase":
            url = f"{self.endpoint}/helm_sync/{self.sync_id}.json"
            if self.auth_token:
                url += f"?auth={urllib.parse.quote(self.auth_token)}"
            req = self._build_request("GET", url)
            status, body = self._execute_http(req)
            if status in (404, 204) or not body or body.strip() == b"null":
                return None
            if status not in (200, 201):
                raise AdapterError(f"Firebase GET failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            return json.loads(body.decode("utf-8"))

        else:  # generic / webhook
            url = f"{self.endpoint}?sync_id={urllib.parse.quote(self.sync_id)}"
            req = self._build_request("GET", url)
            status, body = self._execute_http(req)
            if status in (404, 204) or not body:
                return None
            if status not in (200, 201):
                raise AdapterError(f"Generic REST GET failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            resp_json = json.loads(body.decode("utf-8"))
            if isinstance(resp_json, dict):
                return resp_json.get("payload") or resp_json
            return None

    def push(self, payload: Dict[str, Any]) -> bool:
        """Pushes encrypted state to the remote endpoint."""
        if not self.is_available():
            raise AdapterError("REST adapter is not configured.")

        if self.provider == "supabase":
            url = self.endpoint
            req = self._build_request("POST", url)
            req.add_header("Prefer", "resolution=merge-duplicates,return=minimal")
            row = {
                "sync_id": self.sync_id,
                "payload": payload,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            req.data = json.dumps(row).encode("utf-8")
            status, body = self._execute_http(req)
            if status not in (200, 201, 204):
                raise AdapterError(f"Supabase POST failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            return True

        elif self.provider == "firebase":
            url = f"{self.endpoint}/helm_sync/{self.sync_id}.json"
            if self.auth_token:
                url += f"?auth={urllib.parse.quote(self.auth_token)}"
            req = self._build_request("PUT", url)
            req.data = json.dumps(payload).encode("utf-8")
            status, body = self._execute_http(req)
            if status not in (200, 201, 204):
                raise AdapterError(f"Firebase PUT failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            return True

        else:  # generic / webhook
            url = self.endpoint
            req = self._build_request("POST", url)
            req_data = {
                "sync_id": self.sync_id,
                "payload": payload,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            req.data = json.dumps(req_data).encode("utf-8")
            status, body = self._execute_http(req)
            if status not in (200, 201, 204):
                raise AdapterError(f"Generic REST POST failed with status {status}: {body.decode('utf-8', errors='ignore')}")
            return True


class FileBundleAdapter(SyncAdapter):
    """Local file adapter reading/writing `.helmbundle.json` files."""

    def __init__(self, file_path: Path | str):
        self.file_path = Path(file_path).resolve()

    @property
    def name(self) -> str:
        return "file-bundle"

    def is_available(self) -> bool:
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False

    def pull(self) -> Optional[Dict[str, Any]]:
        if not self.file_path.exists():
            return None
        try:
            content = self.file_path.read_text(encoding="utf-8").strip()
            if not content:
                return None
            data = json.loads(content)
            if isinstance(data, dict):
                # If wrapped in a bundle envelope, return payload
                return data.get("payload", data)
            return None
        except Exception as e:
            raise AdapterError(f"Failed to read file bundle {self.file_path}: {e}") from e

    def push(self, payload: Dict[str, Any]) -> bool:
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.file_path.with_suffix(".tmp")
            bundle_wrapper = {
                "format": SYNC_BUNDLE_FORMAT,
                "version": SYNC_BUNDLE_VERSION,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
            }
            temp.write_text(json.dumps(bundle_wrapper, indent=2, ensure_ascii=False), encoding="utf-8")
            temp.replace(self.file_path)
            return True
        except Exception as e:
            raise AdapterError(f"Failed to write file bundle {self.file_path}: {e}") from e


class MockSyncAdapter(SyncAdapter):
    """In-memory adapter for unit testing and deterministic offline/online simulation."""

    def __init__(self, name: str = "mock-cloud"):
        self._name = name
        self.storage: Optional[Dict[str, Any]] = None
        self.online: bool = True
        self.fail_on_pull: bool = False
        self.fail_on_push: bool = False
        self.pull_count: int = 0
        self.push_count: int = 0

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return self.online

    def pull(self) -> Optional[Dict[str, Any]]:
        if not self.online:
            raise AdapterError("MockSyncAdapter is offline.")
        if self.fail_on_pull:
            raise AdapterError("Simulated pull failure.")
        self.pull_count += 1
        if self.storage is None:
            return None
        return copy.deepcopy(self.storage)

    def push(self, payload: Dict[str, Any]) -> bool:
        if not self.online:
            raise AdapterError("MockSyncAdapter is offline.")
        if self.fail_on_push:
            raise AdapterError("Simulated push failure.")
        self.push_count += 1
        self.storage = copy.deepcopy(payload)
        return True


# ---------------------------------------------------------------------------
# Offline Queue
# ---------------------------------------------------------------------------

class OfflineQueue:
    """Thread-safe, disk-persisted offline change queue."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self._lock = threading.RLock()
        self._items: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (category, key) -> queue item
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not self.file_path.exists():
                return
            try:
                data = json.loads(self.file_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        cat = item.get("category", "fact")
                        k = item.get("key", "")
                        self._items[(cat, k)] = item
            except Exception as e:
                logger.warning("Could not read offline queue from %s: %s", self.file_path, e)

    def _save(self) -> None:
        with self._lock:
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                temp = self.file_path.with_suffix(".tmp")
                temp.write_text(json.dumps(list(self._items.values()), indent=2), encoding="utf-8")
                temp.replace(self.file_path)
            except Exception as e:
                logger.error("Failed to save offline queue to %s: %s", self.file_path, e)

    def enqueue(self, action: str, record: SyncRecord) -> None:
        with self._lock:
            item = {
                "action": action,  # "upsert" or "delete"
                "category": record.category,
                "key": record.key,
                "record": record.to_dict(),
                "enqueued_at": time.time(),
            }
            self._items[(record.category, record.key)] = item
            self._save()

    def peek(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._items.values())

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._save()

    def remove_keys(self, keys: Iterable[Tuple[str, str]]) -> None:
        with self._lock:
            changed = False
            for k in keys:
                if k in self._items:
                    del self._items[k]
                    changed = True
            if changed:
                self._save()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# ---------------------------------------------------------------------------
# HelmSyncManager: Core Engine
# ---------------------------------------------------------------------------

class HelmSyncManager:
    """Offline-first Cross-Device Memory & Fact Sync Manager."""

    def __init__(
        self,
        data_dir: Optional[Path | str] = None,
        device_id: Optional[str] = None,
        passphrase: Optional[str] = None,
        adapter: Optional[SyncAdapter] = None,
        memory_store: Optional[Any] = None,
    ):
        if data_dir is None:
            base = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
            data_dir = base / "sync"
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self.device_id = device_id or self._load_or_create_device_id()
        self.passphrase = passphrase or os.environ.get("HELM_SYNC_PASSPHRASE")
        self.adapter = adapter
        self.memory_store = memory_store

        # In-memory synchronized state
        self.facts: Dict[str, SyncRecord] = {}
        self.preferences: Dict[str, SyncRecord] = {}
        self.settings: Dict[str, SyncRecord] = {}
        self.seen_uuids: Set[str] = set()
        self.sync_history: List[Dict[str, Any]] = []

        # Tracking variables
        self.last_sync_timestamp: Optional[float] = None
        self.last_sync_status: str = "never_synced"
        self.last_error: Optional[str] = None
        self._syncing_with_store: bool = False

        # Offline queue
        self.offline_queue = OfflineQueue(self.data_dir / "offline_queue.json")

        # Load persisted local state
        self._load_local_state()

        # Connect memory store if provided or discover default
        if self.memory_store:
            self.connect_durable_memory_store(self.memory_store)

    def _load_or_create_device_id(self) -> str:
        dev_file = self.data_dir / "device_id.txt"
        if dev_file.exists():
            try:
                val = dev_file.read_text(encoding="utf-8").strip()
                if val:
                    return val
            except Exception:
                pass
        new_id = f"dev_{uuid.uuid4().hex[:12]}"
        try:
            dev_file.write_text(new_id, encoding="utf-8")
        except Exception:
            pass
        return new_id

    def _load_local_state(self) -> None:
        state_file = self.data_dir / "sync_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                self.last_sync_timestamp = data.get("last_sync_timestamp")
                self.last_sync_status = data.get("last_sync_status", "never_synced")
                self.last_error = data.get("last_error")
                self.seen_uuids = set(data.get("seen_uuids", []))
                self.sync_history = data.get("history", [])

                for item in data.get("facts", []):
                    rec = SyncRecord.from_dict(item)
                    if not rec.deleted:
                        self.facts[rec.key] = rec

                for item in data.get("preferences", []):
                    rec = SyncRecord.from_dict(item)
                    if not rec.deleted:
                        self.preferences[rec.key] = rec

                for item in data.get("settings", []):
                    rec = SyncRecord.from_dict(item)
                    if not rec.deleted:
                        self.settings[rec.key] = rec
            except Exception as e:
                logger.warning("Could not parse local sync state from %s: %s", state_file, e)

    def _save_local_state(self) -> None:
        state_file = self.data_dir / "sync_state.json"
        try:
            data = {
                "device_id": self.device_id,
                "last_sync_timestamp": self.last_sync_timestamp,
                "last_sync_status": self.last_sync_status,
                "last_error": self.last_error,
                "seen_uuids": list(self.seen_uuids)[-500:],  # Bound history size
                "history": self.sync_history[-20:],
                "facts": [r.to_dict() for r in self.facts.values()],
                "preferences": [r.to_dict() for r in self.preferences.values()],
                "settings": [r.to_dict() for r in self.settings.values()],
            }
            temp = state_file.with_suffix(".tmp")
            temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            temp.replace(state_file)
        except Exception as e:
            logger.error("Failed to save local sync state to %s: %s", state_file, e)

    # -----------------------------------------------------------------------
    # Integration with durable_memory.py
    # -----------------------------------------------------------------------

    def connect_durable_memory_store(self, store: Any) -> None:
        """Connects a DurableMemoryStore, seeds local facts, and registers change listener."""
        with self._lock:
            self.memory_store = store
            if hasattr(store, "register_sync_listener"):
                store.register_sync_listener(self._handle_memory_store_mutation)

            # Seed existing facts into local sync records if not already populated
            try:
                facts_dict = store.list_facts()
                for k, v in facts_dict.items():
                    if k not in self.facts:
                        rec = SyncRecord(
                            category="fact",
                            key=k,
                            value=v,
                            device_id=self.device_id,
                            updated_at=time.time(),
                        )
                        self.facts[k] = rec
                        self.seen_uuids.add(rec.id)
                self._save_local_state()
            except Exception as e:
                logger.debug("Failed to seed facts from memory store: %s", e)

    def _handle_memory_store_mutation(self, key: str, value: str, deleted: bool) -> None:
        """Listener callback invoked when DurableMemoryStore is modified."""
        if self._syncing_with_store:
            return
        with self._lock:
            rec = SyncRecord(
                category="fact",
                key=key,
                value=value if not deleted else "",
                device_id=self.device_id,
                updated_at=time.time(),
                deleted=deleted,
            )
            self.seen_uuids.add(rec.id)
            if deleted:
                if key in self.facts:
                    del self.facts[key]
                self.offline_queue.enqueue("delete", rec)
            else:
                self.facts[key] = rec
                self.offline_queue.enqueue("upsert", rec)
            self._save_local_state()

    # -----------------------------------------------------------------------
    # Facts, Preferences & Settings API
    # -----------------------------------------------------------------------

    def set_fact(self, key: str, value: str) -> Tuple[bool, str]:
        """Sets a durable fact locally and stages it for remote sync."""
        with self._lock:
            # If memory store is connected, route through memory store
            if self.memory_store and hasattr(self.memory_store, "set_fact"):
                return self.memory_store.set_fact(key, value)

            clean_k = str(key).strip()
            clean_v = str(value).strip()
            if not clean_k or not clean_v:
                return False, "Key and value cannot be empty."

            rec = SyncRecord(
                category="fact",
                key=clean_k,
                value=clean_v,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            self.facts[clean_k] = rec
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("upsert", rec)
            self._save_local_state()
            return True, f"Fact '{clean_k}' saved locally and queued for sync."

    def delete_fact(self, key: str) -> Tuple[bool, str]:
        """Deletes a durable fact and queues a tombstone for sync."""
        with self._lock:
            if self.memory_store and hasattr(self.memory_store, "delete_fact"):
                return self.memory_store.delete_fact(key)

            clean_k = str(key).strip()
            if clean_k not in self.facts:
                return False, f"Fact '{clean_k}' not found."

            rec = SyncRecord(
                category="fact",
                key=clean_k,
                value="",
                deleted=True,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            del self.facts[clean_k]
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("delete", rec)
            self._save_local_state()
            return True, f"Fact '{clean_k}' deleted and queued for sync."

    def get_fact(self, key: str) -> Optional[str]:
        with self._lock:
            if self.memory_store and hasattr(self.memory_store, "get_fact"):
                return self.memory_store.get_fact(key)
            rec = self.facts.get(str(key).strip())
            return rec.value if rec and not rec.deleted else None

    def list_facts(self) -> Dict[str, str]:
        with self._lock:
            if self.memory_store and hasattr(self.memory_store, "list_facts"):
                return self.memory_store.list_facts()
            return {k: r.value for k, r in self.facts.items() if not r.deleted}

    def set_preference(self, key: str, value: Any) -> None:
        """Sets a user preference and queues for sync."""
        with self._lock:
            clean_k = str(key).strip()
            rec = SyncRecord(
                category="preference",
                key=clean_k,
                value=value,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            self.preferences[clean_k] = rec
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("upsert", rec)
            self._save_local_state()

    def get_preference(self, key: str, default: Any = None) -> Any:
        with self._lock:
            rec = self.preferences.get(str(key).strip())
            if rec and not rec.deleted:
                return rec.value
            return default

    def list_preferences(self) -> Dict[str, Any]:
        with self._lock:
            return {k: r.value for k, r in self.preferences.items() if not r.deleted}

    def delete_preference(self, key: str) -> bool:
        """Deletes a preference and stages a tombstone for sync."""
        with self._lock:
            clean_k = str(key).strip()
            if clean_k not in self.preferences:
                return False
            rec = SyncRecord(
                category="preference",
                key=clean_k,
                value=None,
                deleted=True,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            del self.preferences[clean_k]
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("delete", rec)
            self._save_local_state()
            return True

    def set_setting(self, key: str, value: Any) -> None:
        """Sets a custom setting and queues for sync."""
        with self._lock:
            clean_k = str(key).strip()
            rec = SyncRecord(
                category="setting",
                key=clean_k,
                value=value,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            self.settings[clean_k] = rec
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("upsert", rec)
            self._save_local_state()

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._lock:
            rec = self.settings.get(str(key).strip())
            if rec and not rec.deleted:
                return rec.value
            return default

    def list_settings(self) -> Dict[str, Any]:
        with self._lock:
            return {k: r.value for k, r in self.settings.items() if not r.deleted}

    def delete_setting(self, key: str) -> bool:
        """Deletes a setting and stages a tombstone for sync."""
        with self._lock:
            clean_k = str(key).strip()
            if clean_k not in self.settings:
                return False
            rec = SyncRecord(
                category="setting",
                key=clean_k,
                value=None,
                deleted=True,
                device_id=self.device_id,
                updated_at=time.time(),
            )
            del self.settings[clean_k]
            self.seen_uuids.add(rec.id)
            self.offline_queue.enqueue("delete", rec)
            self._save_local_state()
            return True

    def set_adapter(self, adapter: Optional[SyncAdapter]) -> None:
        with self._lock:
            self.adapter = adapter

    def set_passphrase(self, passphrase: Optional[str]) -> None:
        with self._lock:
            self.passphrase = passphrase

    # -----------------------------------------------------------------------
    # Core Synchronization Cycle
    # -----------------------------------------------------------------------

    def trigger_sync(self, force: bool = False) -> Tuple[bool, str]:
        """Executes a full bidirectional sync cycle with remote endpoint:
        1. Checks connectivity and encryption key.
        2. Pulls and decrypts remote state.
        3. Resolves conflicts using timestamped LWW & UUID deduplication.
        4. Applies merged state to local stores and DurableMemoryStore.
        5. Encrypts and pushes merged local state to remote endpoint.
        6. Clears offline queue on success and records sync status.
        """
        with self._lock:
            if not self.adapter:
                self.last_sync_status = "error"
                self.last_error = "No sync adapter configured."
                self._save_local_state()
                return False, self.last_error

            if not self.adapter.is_available():
                self.last_sync_status = "offline"
                self.last_error = f"Adapter '{self.adapter.name}' is unavailable/offline."
                self._save_local_state()
                return False, self.last_error

            if not self.passphrase:
                self.last_sync_status = "error"
                self.last_error = "Sync encryption passphrase is required."
                self._save_local_state()
                return False, self.last_error

            pulled_count = 0
            pushed_count = 0

            # Step 1: Pull and decrypt remote state
            try:
                remote_envelope = self.adapter.pull()
            except Exception as e:
                self.last_sync_status = "offline"
                self.last_error = f"Pull failed: {e}"
                self._save_local_state()
                return False, self.last_error

            if remote_envelope:
                try:
                    decrypted_remote = SyncCrypto.decrypt_payload(remote_envelope, self.passphrase)
                except Exception as e:
                    self.last_sync_status = "error"
                    self.last_error = f"Decryption of remote state failed: {e}"
                    self._save_local_state()
                    return False, self.last_error

                # Step 2: Merge remote records into local state (LWW)
                remote_records = decrypted_remote.get("records", [])
                memory_updates: Dict[str, str] = {}
                memory_deletes: List[str] = []

                for item in remote_records:
                    inc_rec = SyncRecord.from_dict(item)

                    # Deduplication check
                    if inc_rec.id in self.seen_uuids and not force:
                        continue

                    category = inc_rec.category
                    key = inc_rec.key

                    if category == "fact":
                        local_rec = self.facts.get(key)
                        winner, changed = resolve_record_conflict(local_rec, inc_rec)
                        if changed:
                            pulled_count += 1
                            self.seen_uuids.add(winner.id)
                            if winner.deleted:
                                if key in self.facts:
                                    del self.facts[key]
                                memory_deletes.append(key)
                            else:
                                self.facts[key] = winner
                                memory_updates[key] = str(winner.value)

                    elif category == "preference":
                        local_rec = self.preferences.get(key)
                        winner, changed = resolve_record_conflict(local_rec, inc_rec)
                        if changed:
                            pulled_count += 1
                            self.seen_uuids.add(winner.id)
                            if winner.deleted:
                                if key in self.preferences:
                                    del self.preferences[key]
                            else:
                                self.preferences[key] = winner

                    elif category == "setting":
                        local_rec = self.settings.get(key)
                        winner, changed = resolve_record_conflict(local_rec, inc_rec)
                        if changed:
                            pulled_count += 1
                            self.seen_uuids.add(winner.id)
                            if winner.deleted:
                                if key in self.settings:
                                    del self.settings[key]
                            else:
                                self.settings[key] = winner

                # Apply remote updates to DurableMemoryStore safely
                if self.memory_store and (memory_updates or memory_deletes):
                    self._syncing_with_store = True
                    try:
                        if hasattr(self.memory_store, "import_facts") and memory_updates:
                            self.memory_store.import_facts(memory_updates, merge=True)
                        elif hasattr(self.memory_store, "set_fact"):
                            for k, v in memory_updates.items():
                                self.memory_store.set_fact(k, v)
                        if hasattr(self.memory_store, "delete_fact"):
                            for k in memory_deletes:
                                self.memory_store.delete_fact(k)
                    finally:
                        self._syncing_with_store = False

            # Step 3: Prepare local package for push
            all_records: List[Dict[str, Any]] = []
            for r in self.facts.values():
                all_records.append(r.to_dict())
            for r in self.preferences.values():
                all_records.append(r.to_dict())
            for r in self.settings.values():
                all_records.append(r.to_dict())

            # Include offline queue tombstones so deletions propagate
            for q_item in self.offline_queue.peek():
                rec_dict = q_item.get("record", {})
                if rec_dict.get("deleted"):
                    all_records.append(rec_dict)

            package = {
                "version": SYNC_BUNDLE_VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "device_id": self.device_id,
                "records": all_records,
            }

            # Step 4: Encrypt and push to remote adapter
            try:
                encrypted_payload = SyncCrypto.encrypt_payload(package, self.passphrase)
                self.adapter.push(encrypted_payload)
                pushed_count = len(all_records)
            except Exception as e:
                self.last_sync_status = "error"
                self.last_error = f"Push failed: {e}"
                self._save_local_state()
                return False, self.last_error

            # Step 5: Finalize sync state and clear offline queue
            self.offline_queue.clear()
            self.last_sync_timestamp = time.time()
            self.last_sync_status = "synced"
            self.last_error = None

            history_entry = {
                "timestamp": self.last_sync_timestamp,
                "time_iso": datetime.now(timezone.utc).isoformat(),
                "adapter": self.adapter.name,
                "pulled": pulled_count,
                "pushed": pushed_count,
                "status": "success",
            }
            self.sync_history.append(history_entry)
            self._save_local_state()

            msg = f"Sync successful: {pulled_count} records pulled, {pushed_count} pushed."
            logger.info(msg)
            return True, msg

    # -----------------------------------------------------------------------
    # Status API
    # -----------------------------------------------------------------------

    def get_sync_status(self) -> Dict[str, Any]:
        """Returns comprehensive status dictionary for UI / CLI / health monitoring."""
        with self._lock:
            iso_time = (
                datetime.fromtimestamp(self.last_sync_timestamp, tz=timezone.utc).isoformat()
                if self.last_sync_timestamp
                else None
            )
            return {
                "status": self.last_sync_status,
                "last_sync_time": iso_time,
                "last_sync_timestamp": self.last_sync_timestamp,
                "pending_changes_count": len(self.offline_queue),
                "remote_configured": self.adapter is not None,
                "adapter_name": self.adapter.name if self.adapter else None,
                "encryption_enabled": bool(self.passphrase),
                "device_id": self.device_id,
                "last_error": self.last_error,
                "stats": {
                    "facts_count": len(self.facts),
                    "preferences_count": len(self.preferences),
                    "settings_count": len(self.settings),
                    "seen_uuids_count": len(self.seen_uuids),
                },
                "history": list(self.sync_history[-10:]),
            }

    # -----------------------------------------------------------------------
    # Local Bundle Export & Import (.helmbundle.json)
    # -----------------------------------------------------------------------

    def export_backup(
        self,
        file_path: Optional[str | Path] = None,
        passphrase: Optional[str] = None,
    ) -> str:
        """Exports local state to a `.helmbundle.json` file.
        If passphrase is provided (or manager passphrase exists), bundle is end-to-end encrypted.
        Returns the absolute path to the exported bundle.
        """
        with self._lock:
            if file_path is None:
                fname = f"helm_backup_{int(time.time())}{BUNDLE_EXTENSION}"
                target_path = self.data_dir / fname
            else:
                target_path = Path(file_path).resolve()

            target_path.parent.mkdir(parents=True, exist_ok=True)
            active_passphrase = passphrase or self.passphrase

            package = {
                "version": SYNC_BUNDLE_VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "device_id": self.device_id,
                "records": [
                    r.to_dict()
                    for r in list(self.facts.values()) + list(self.preferences.values()) + list(self.settings.values())
                ],
            }

            if active_passphrase:
                encrypted_envelope = SyncCrypto.encrypt_payload(package, active_passphrase)
                bundle_data = {
                    "format": SYNC_BUNDLE_FORMAT,
                    "version": SYNC_BUNDLE_VERSION,
                    "encrypted": True,
                    "exported_at": package["exported_at"],
                    "device_id": self.device_id,
                    "payload": encrypted_envelope,
                }
            else:
                bundle_data = {
                    "format": SYNC_BUNDLE_FORMAT,
                    "version": SYNC_BUNDLE_VERSION,
                    "encrypted": False,
                    "exported_at": package["exported_at"],
                    "device_id": self.device_id,
                    "payload": package,
                }

            temp_path = target_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(bundle_data, indent=2, ensure_ascii=False), encoding="utf-8")
            temp_path.replace(target_path)

            logger.info("Exported backup bundle to %s", target_path)
            return str(target_path)

    def import_backup(
        self,
        file_path: str | Path,
        passphrase: Optional[str] = None,
        merge: bool = True,
    ) -> Dict[str, Any]:
        """Imports and restores state from a `.helmbundle.json` file.
        If merge is True, resolves incoming records with LWW; if False, overwrites local state.
        Returns summary of restored records.
        """
        source_path = Path(file_path).resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"Backup bundle not found: {source_path}")

        try:
            content = source_path.read_text(encoding="utf-8")
            bundle_data = json.loads(content)
        except Exception as e:
            raise ValueError(f"Corrupted backup bundle {source_path}: {e}") from e

        if not isinstance(bundle_data, dict) or bundle_data.get("format") != SYNC_BUNDLE_FORMAT:
            raise ValueError(f"Invalid bundle format in {source_path}. Expected format: '{SYNC_BUNDLE_FORMAT}'")

        is_encrypted = bundle_data.get("encrypted", False)
        payload = bundle_data.get("payload", {})

        if is_encrypted:
            active_passphrase = passphrase or self.passphrase
            if not active_passphrase:
                raise ValueError("A passphrase is required to decrypt this encrypted backup bundle.")
            package = SyncCrypto.decrypt_payload(payload, active_passphrase)
        else:
            package = payload

        records = package.get("records", [])

        with self._lock:
            if not merge:
                self.facts.clear()
                self.preferences.clear()
                self.settings.clear()

            facts_restored = 0
            preferences_restored = 0
            settings_restored = 0
            memory_updates: Dict[str, str] = {}
            memory_deletes: List[str] = []

            for item in records:
                rec = SyncRecord.from_dict(item)
                cat = rec.category
                k = rec.key

                if cat == "fact":
                    local_rec = self.facts.get(k)
                    winner, changed = resolve_record_conflict(local_rec, rec) if merge else (rec, True)
                    if changed:
                        self.seen_uuids.add(winner.id)
                        if winner.deleted:
                            if k in self.facts:
                                del self.facts[k]
                            memory_deletes.append(k)
                        else:
                            self.facts[k] = winner
                            memory_updates[k] = str(winner.value)
                            facts_restored += 1

                elif cat == "preference":
                    local_rec = self.preferences.get(k)
                    winner, changed = resolve_record_conflict(local_rec, rec) if merge else (rec, True)
                    if changed:
                        self.seen_uuids.add(winner.id)
                        if winner.deleted:
                            if k in self.preferences:
                                del self.preferences[k]
                        else:
                            self.preferences[k] = winner
                            preferences_restored += 1

                elif cat == "setting":
                    local_rec = self.settings.get(k)
                    winner, changed = resolve_record_conflict(local_rec, rec) if merge else (rec, True)
                    if changed:
                        self.seen_uuids.add(winner.id)
                        if winner.deleted:
                            if k in self.settings:
                                del self.settings[k]
                        else:
                            self.settings[k] = winner
                            settings_restored += 1

            # Sync facts into connected memory store
            if self.memory_store and (memory_updates or memory_deletes):
                self._syncing_with_store = True
                try:
                    if hasattr(self.memory_store, "import_facts") and memory_updates:
                        self.memory_store.import_facts(memory_updates, merge=merge)
                    elif hasattr(self.memory_store, "set_fact"):
                        for k, v in memory_updates.items():
                            self.memory_store.set_fact(k, v)
                    if hasattr(self.memory_store, "delete_fact"):
                        for k in memory_deletes:
                            self.memory_store.delete_fact(k)
                finally:
                    self._syncing_with_store = False

            self._save_local_state()

            summary = {
                "facts_restored": facts_restored,
                "preferences_restored": preferences_restored,
                "settings_restored": settings_restored,
                "source_device": bundle_data.get("device_id", "Unknown"),
                "exported_at": bundle_data.get("exported_at"),
            }
            logger.info("Imported backup from %s: %s", source_path, summary)
            return summary


# ---------------------------------------------------------------------------
# Module-Level Convenience Functions & Singleton
# ---------------------------------------------------------------------------

_DEFAULT_SYNC_MANAGER: Optional[HelmSyncManager] = None
_SYNC_LOCK = threading.RLock()


def get_sync_manager(data_dir: Optional[str | Path] = None) -> HelmSyncManager:
    """Returns singleton sync manager instance."""
    global _DEFAULT_SYNC_MANAGER
    with _SYNC_LOCK:
        if _DEFAULT_SYNC_MANAGER is None:
            import durable_memory
            store = durable_memory.get_default_memory_store()
            _DEFAULT_SYNC_MANAGER = HelmSyncManager(data_dir=data_dir, memory_store=store)
        return _DEFAULT_SYNC_MANAGER


def set_sync_manager(manager: Optional[HelmSyncManager]) -> None:
    """Allows tests to inject or reset the default sync manager."""
    global _DEFAULT_SYNC_MANAGER
    with _SYNC_LOCK:
        _DEFAULT_SYNC_MANAGER = manager


def get_sync_status() -> Dict[str, Any]:
    """Returns current sync status."""
    return get_sync_manager().get_sync_status()


def trigger_sync(force: bool = False) -> Tuple[bool, str]:
    """Triggers bidirectional sync."""
    return get_sync_manager().trigger_sync(force=force)


def export_backup(file_path: Optional[str | Path] = None, passphrase: Optional[str] = None) -> str:
    """Exports backup bundle."""
    return get_sync_manager().export_backup(file_path=file_path, passphrase=passphrase)


def import_backup(
    file_path: str | Path,
    passphrase: Optional[str] = None,
    merge: bool = True,
) -> Dict[str, Any]:
    """Imports backup bundle."""
    return get_sync_manager().import_backup(file_path=file_path, passphrase=passphrase, merge=merge)
