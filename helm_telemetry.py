"""helm_telemetry.py - Privacy-Preserving Opt-In Anonymous Telemetry & Crash Reporting.

Architecture:
1. STRICT PRIVACY INVARIANT: Disabled by default. No events, metrics, or logs leave the device
   unless the user explicitly toggles opt-in consent.
2. ZERO-PII GUARANTEE: Never transmits usernames, prompt content, clipboard data, screen OCR,
   or user document paths.
3. ANONYMIZED MACHINE ID: Generated using a one-way salt + SHA-256 hash.
4. LOCAL SPOOLING: Events are spooled locally to .helm_data/telemetry_spool.jsonl for auditability.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("helm.telemetry")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, ".helm_data")
SPOOL_FILE = os.path.join(DATA_DIR, "telemetry_spool.jsonl")
SETTINGS_FILE = os.path.join(BASE_DIR, "config", "settings.yaml")

# Sensitive fields that must NEVER appear in telemetry payloads
_PROHIBITED_PAYLOAD_KEYS = {
    "prompt", "query", "user_text", "text", "message", "transcript",
    "clipboard", "screen", "ocr", "image", "file_content", "path", "password",
    "token", "secret", "key", "email", "recipient", "subject", "body", "url"
}


def generate_anonymous_id() -> str:
    """Generates a non-reversible, salt-hashed machine pseudonym without PII."""
    salt = "helm_telemetry_v1_privacy_salt"
    raw = f"{platform.node()}-{getpass.getuser()}-{platform.machine()}-{salt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class TelemetryManager:
    """Thread-safe, opt-in anonymous telemetry engine."""

    _instance: TelemetryManager | None = None
    _lock = threading.Lock()

    def __init__(self, data_dir: str = DATA_DIR, settings_path: str = SETTINGS_FILE):
        self._data_dir = data_dir
        self._settings_path = settings_path
        self._spool_path = os.path.join(self._data_dir, "telemetry_spool.jsonl")
        self._enabled = False
        self._anonymous_id = generate_anonymous_id()
        self._state_lock = threading.Lock()
        self._load_consent_state()

    @classmethod
    def instance(cls) -> TelemetryManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            cls._instance = None

    def _load_consent_state(self) -> None:
        """Loads user consent from config/settings.yaml or environment."""
        # 1. Environment variable override
        env_val = os.environ.get("HELM_TELEMETRY_ENABLED", "").lower().strip()
        if env_val in ("1", "true", "yes"):
            self._enabled = True
            return
        if env_val in ("0", "false", "no"):
            self._enabled = False
            return

        # 2. Check settings file
        if self._settings_path and os.path.isfile(self._settings_path):
            try:
                import yaml
                with open(self._settings_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                tel_cfg = cfg.get("telemetry", {})
                self._enabled = bool(tel_cfg.get("enabled", False))
                if "anonymous_id" in tel_cfg:
                    self._anonymous_id = tel_cfg["anonymous_id"]
                return
            except Exception as e:
                logger.debug("Could not read settings file for telemetry: %s", e)

        # Default: STRICTLY disabled
        self._enabled = False

    def is_enabled(self) -> bool:
        """Returns True if the user has explicitly opted into anonymous telemetry."""
        with self._state_lock:
            return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Updates user telemetry consent and persists to settings.yaml."""
        with self._state_lock:
            self._enabled = bool(enabled)
            self._persist_consent_state()

    def _persist_consent_state(self) -> None:
        """Saves telemetry consent to settings file."""
        if not self._settings_path:
            return
        os.makedirs(os.path.dirname(self._settings_path), exist_ok=True)
        try:
            import yaml
            cfg = {}
            if os.path.isfile(self._settings_path):
                try:
                    with open(self._settings_path, "r", encoding="utf-8") as f:
                        cfg = yaml.safe_load(f) or {}
                except Exception:
                    cfg = {}

            cfg["telemetry"] = {
                "enabled": self._enabled,
                "anonymous_id": self._anonymous_id,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

            with open(self._settings_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, default_flow_style=False)
        except Exception as e:
            logger.error("Failed to persist telemetry consent: %s", e)

    def sanitize_payload(self, properties: dict[str, Any] | None) -> dict[str, Any]:
        """Strips all sensitive keys and bounds length to prevent accidental leakage."""
        if not properties or not isinstance(properties, dict):
            return {}

        clean = {}
        for k, v in properties.items():
            k_low = str(k).lower().strip()
            # Drop prohibited keys
            if any(p in k_low for p in _PROHIBITED_PAYLOAD_KEYS):
                continue

            # Only allow primitive serializable types
            if isinstance(v, (bool, int, float)):
                clean[k] = v
            elif isinstance(v, str):
                # Truncate string and reject if it looks like a path or URL
                if "://" in v or "\\" in v or "/" in v:
                    clean[k] = "[redacted_path_or_url]"
                else:
                    clean[k] = v[:64]
        return clean

    def track_event(self, event_name: str, properties: dict[str, Any] | None = None) -> bool:
        """Records an anonymous usage event if telemetry is enabled."""
        if not self.is_enabled():
            return False

        safe_props = self.sanitize_payload(properties)
        event = {
            "anonymous_id": self._anonymous_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_name[:32],
            "os": platform.system(),
            "os_release": platform.release(),
            "python_version": platform.python_version(),
            "properties": safe_props,
        }

        self._spool_event(event)
        return True

    def track_error(self, error_type: str, component: str = "") -> bool:
        """Records an anonymized error/crash signature if telemetry is enabled."""
        if not self.is_enabled():
            return False

        return self.track_event("error_occurred", {
            "error_type": error_type[:32],
            "component": component[:32],
        })

    def _spool_event(self, event: dict[str, Any]) -> None:
        """Appends event to the local spool file with rotation."""
        os.makedirs(self._data_dir, exist_ok=True)
        try:
            line = json.dumps(event) + "\n"
            with open(self._spool_path, "a", encoding="utf-8") as f:
                f.write(line)

            # Rotate spool if too large (> 1000 lines)
            self._maybe_rotate_spool()
        except Exception as e:
            logger.debug("Failed to spool telemetry event: %s", e)

    def _maybe_rotate_spool(self) -> None:
        """Rotates the spool file to keep local size bounded."""
        try:
            if not os.path.isfile(self._spool_path):
                return
            if os.path.getsize(self._spool_path) > 500_000:  # > 500KB
                lines = []
                with open(self._spool_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                if len(lines) > 500:
                    with open(self._spool_path, "w", encoding="utf-8") as f:
                        f.writelines(lines[-500:])
        except Exception:
            pass

    def get_status(self) -> dict[str, Any]:
        """Returns the current telemetry status for display in settings."""
        with self._state_lock:
            spool_count = 0
            if os.path.isfile(self._spool_path):
                try:
                    with open(self._spool_path, "r", encoding="utf-8") as f:
                        spool_count = sum(1 for _ in f)
                except Exception:
                    pass

            return {
                "enabled": self._enabled,
                "anonymous_id": self._anonymous_id,
                "spooled_events_count": spool_count,
                "privacy_policy": "https://github.com/helm-ai/helm/blob/master/SECURITY_NOTES.md",
            }


# Module-level convenience helpers
def track_event(event_name: str, properties: dict[str, Any] | None = None) -> bool:
    return TelemetryManager.instance().track_event(event_name, properties)

def track_error(error_type: str, component: str = "") -> bool:
    return TelemetryManager.instance().track_error(error_type, component)

def is_telemetry_enabled() -> bool:
    return TelemetryManager.instance().is_enabled()

def set_telemetry_enabled(enabled: bool) -> None:
    TelemetryManager.instance().set_enabled(enabled)

def get_telemetry_status() -> dict[str, Any]:
    return TelemetryManager.instance().get_status()
