"""rails_config.py - Tier 6 Centralized Policy and Runtime Configuration.

Provides a unified, human-editable configuration file (homie_config.json)
with automatic hot-reloading (mtime checks):
- Model parameters (provider, model name, temperature, tokens).
- Quiet hours (enabled, start_hour, end_hour).
- Heartbeat thresholds (disk_threshold_gb, ram_threshold_pct, loop_interval).
- Consequential tools requiring explicit per-action confirmation.
- Untrusted content and prompt-injection defense settings.
- Running cost and token rates.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("homie.rails_config")

# Immutable compiled-in consequential safety floor: tools that modify system state, files, or facts
# and strictly require human confirmation before execution.
COMPILED_IN_CONSEQUENTIAL_TOOLS: frozenset[str] = frozenset({
    "homie_set_clipboard",
    "homie_launch_app",
    "homie_send_chat",
    "homie_close_app",
    "homie_kill_process",
    "homie_safe_command",
    "homie_agent_click",
    "homie_agent_type",
    "homie_agent_mouse_move",
    "homie_send_hotkey",
    "homie_execute_cmd",
    "homie_delete_file",
    "homie_remember_fact",
    "homie_forget_fact",
    "homie_remote_trackpad",
})

# Sensitive read tools: read private user context; incur taint propagation and rate limits
# but do NOT require disruptive per-action human confirmation dialogs.
COMPILED_IN_SENSITIVE_READS: frozenset[str] = frozenset({
    "homie_capture_screen",
    "homie_get_clipboard",
    "homie_read_screen_memory",
})

# Reversible UI/media controls: low risk, can be easily undone or adjusted.
COMPILED_IN_REVERSIBLE_TOOLS: frozenset[str] = frozenset({
    "homie_control_media",
    "homie_place_window",
    "homie_play_youtube",
    "homie_snap_window",
})

# Safe passive read-only tools:
COMPILED_IN_READ_ONLY_TOOLS: frozenset[str] = frozenset({
    "homie_get_vitals",
    "homie_list_downloads",
    "homie_list_facts",
    "homie_get_meeting_notes",
    "homie_assistant_timeline",
    "homie_get_top_processes",
    "homie_list_windows",
})

# Full set of compiled-in classified tools: every tool in homie_supervisor must belong here!
ALL_CLASSIFIED_TOOLS: frozenset[str] = (
    COMPILED_IN_CONSEQUENTIAL_TOOLS
    | COMPILED_IN_SENSITIVE_READS
    | COMPILED_IN_REVERSIBLE_TOOLS
    | COMPILED_IN_READ_ONLY_TOOLS
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "model": {
        "provider": "openrouter",
        "name": "google/gemini-2.5-flash",
        "temperature": 0.4,
        "max_tokens": 1024,
    },
    "quiet_hours": {
        "enabled": True,
        "start_hour": 22,
        "end_hour": 8,
    },
    "heartbeat": {
        "enabled": True,
        "loop_interval_seconds": 1.0,
        "disk_threshold_gb": 5.0,
        "ram_threshold_pct": 95.0,
    },
    "safety": {
        "require_confirmation": [
            "homie_set_clipboard",
            "homie_launch_app",
            "homie_send_chat",
            "homie_close_app",
            "homie_kill_process",
            "homie_safe_command",
            "homie_agent_click",
            "homie_agent_type",
            "homie_agent_mouse_move",
            "homie_send_hotkey",
        ],
        "untrusted_content_tags": True,
        "block_instruction_injection": True,
    },
    "cost_tracking": {
        "enabled": True,
        "input_cost_per_million": 0.15,
        "output_cost_per_million": 0.60,
    },
}


def get_default_config_path() -> Path:
    """Returns the canonical path for homie_config.json."""
    custom = os.environ.get("HOMIE_CONFIG_PATH")
    if custom:
        return Path(custom).resolve()
    base_dir = os.environ.get("HOMIE_DIR")
    if base_dir:
        return (Path(base_dir) / "homie_config.json").resolve()
    return (Path.home() / ".config" / "homie" / "homie_config.json").resolve()


class RailsConfig:
    """Thread-safe, self-reloading configuration manager."""

    def __init__(self, config_path: Optional[Path | str] = None):
        self.config_path = Path(config_path).resolve() if config_path else get_default_config_path()
        self._lock = threading.RLock()
        self._cached_config: Dict[str, Any] = {}
        self._last_mtime: float = -1.0
        self._ensure_config_exists()

    def _ensure_config_exists(self) -> None:
        """Creates default config if file is missing."""
        with self._lock:
            if not self.config_path.exists():
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.config_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
                tmp.replace(self.config_path)
            self._reload_if_needed()

    def _reload_if_needed(self) -> None:
        """Reloads config if the file on disk was modified."""
        with self._lock:
            try:
                if not self.config_path.exists():
                    self._cached_config = DEFAULT_CONFIG.copy()
                    return
                mtime = self.config_path.stat().st_mtime
                if mtime != self._last_mtime:
                    text = self.config_path.read_text(encoding="utf-8")
                    data = json.loads(text)
                    if isinstance(data, dict):
                        self._cached_config = data
                        self._last_mtime = mtime
                        logger.debug("RailsConfig reloaded from %s", self.config_path)
            except Exception as e:
                logger.warning("Failed to reload RailsConfig: %s; using previous cache", e)
                if not self._cached_config:
                    self._cached_config = DEFAULT_CONFIG.copy()

    def get_raw_config(self) -> Dict[str, Any]:
        """Returns snapshot of current config (reloads if changed on disk)."""
        self._reload_if_needed()
        with self._lock:
            return self._cached_config.copy()

    def save_config(self, config: Dict[str, Any]) -> None:
        """Atomically saves config to disk and refreshes memory cache."""
        with self._lock:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.config_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
            tmp.replace(self.config_path)
            self._cached_config = config
            self._last_mtime = self.config_path.stat().st_mtime

    def update(self, key_path: str, value: Any) -> None:
        """Updates a nested key like 'heartbeat.disk_threshold_gb'."""
        with self._lock:
            cfg = self.get_raw_config()
            parts = key_path.split(".")
            curr = cfg
            for part in parts[:-1]:
                curr = curr.setdefault(part, {})
            curr[parts[-1]] = value
            self.save_config(cfg)

    # =========================================================================
    # High-level accessor helpers
    # =========================================================================

    def is_confirmation_required(self, tool_name: str) -> bool:
        """Checks if a tool is on the consequential confirmation list.
        The compiled-in safety floor CANNOT be removed or bypassed by disk config.
        Disk config may only ADD additional tools to require confirmation.
        """
        from action_broker import ActionBroker
        canonical = ActionBroker.LEGACY_TOOL_MAP.get(tool_name, tool_name)
        if not canonical.startswith("homie_"):
            canonical_cand = f"homie_{canonical}"
            if canonical_cand in COMPILED_IN_CONSEQUENTIAL_TOOLS:
                canonical = canonical_cand

        if canonical in COMPILED_IN_CONSEQUENTIAL_TOOLS or tool_name in COMPILED_IN_CONSEQUENTIAL_TOOLS:
            return True
        self._reload_if_needed()
        with self._lock:
            safety = self._cached_config.get("safety", {})
            required_tools = safety.get("require_confirmation", [])
            return tool_name in required_tools or canonical in required_tools

    def get_heartbeat_thresholds(self) -> Tuple[float, float]:
        """Returns (disk_threshold_gb, ram_threshold_pct)."""
        self._reload_if_needed()
        with self._lock:
            hb = self._cached_config.get("heartbeat", {})
            disk = float(hb.get("disk_threshold_gb", 5.0))
            ram = float(hb.get("ram_threshold_pct", 95.0))
            return disk, ram

    def get_quiet_hours(self) -> Tuple[bool, int, int]:
        """Returns (enabled, start_hour, end_hour)."""
        self._reload_if_needed()
        with self._lock:
            qh = self._cached_config.get("quiet_hours", {})
            enabled = bool(qh.get("enabled", True))
            start_hour = int(qh.get("start_hour", 22))
            end_hour = int(qh.get("end_hour", 8))
            return enabled, start_hour, end_hour

    def get_model_config(self) -> Dict[str, Any]:
        """Returns model configuration dictionary."""
        self._reload_if_needed()
        with self._lock:
            return self._cached_config.get("model", DEFAULT_CONFIG["model"]).copy()

    def get_cost_rates(self) -> Tuple[float, float]:
        """Returns (input_cost_per_million, output_cost_per_million)."""
        self._reload_if_needed()
        with self._lock:
            ct = self._cached_config.get("cost_tracking", {})
            input_rate = float(ct.get("input_cost_per_million", 0.15))
            output_rate = float(ct.get("output_cost_per_million", 0.60))
            return input_rate, output_rate


_GLOBAL_CONFIG: Optional[RailsConfig] = None
_CONFIG_LOCK = threading.RLock()


def get_rails_config(path: Optional[Path | str] = None) -> RailsConfig:
    global _GLOBAL_CONFIG
    with _CONFIG_LOCK:
        if _GLOBAL_CONFIG is None or path is not None:
            _GLOBAL_CONFIG = RailsConfig(path)
        return _GLOBAL_CONFIG
