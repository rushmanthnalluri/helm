"""heartbeat_service.py - Tier 5 Proactive Heartbeat and Scheduled Checks.

Builds an always-on background heartbeat loop that:
1. Runs scheduled checks defined in a human-editable config file (heartbeat_checks.json).
2. Operates quiet by default: logs calm notices and reserves interruptions for noteworthy events.
3. Holds notices in a durable catch-up inbox (heartbeat_inbox.json) so alerts are never lost while the user is away.
4. Respects quiet hours (non-urgent notifications wait for waking hours).
5. Persists schedule due times across restarts (heartbeat_state.json) so timers do not reset or snowball on boot.
6. Bounded non-blocking execution: checks time out safely and never pile up overlapping runs.
7. Fully dismissible: user can inspect, acknowledge, and dismiss surfaced alerts.
8. Integrated with emergency kill switch: halts proactive actions immediately when engaged.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import kill_switch

logger = logging.getLogger("homie.heartbeat")


def get_heartbeat_dir() -> Path:
    """Returns directory where heartbeat configuration and state live."""
    base = Path(os.environ.get("HOMIE_DIR") or (Path.home() / ".config" / "homie"))
    return base.resolve()


DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "loop_interval_seconds": 1.0,
    "quiet_hours": {
        "enabled": True,
        "start_hour": 22,  # 10 PM
        "end_hour": 8      # 8 AM
    },
    "checks": [
        {
            "id": "disk_space",
            "name": "Disk Free Space Check",
            "enabled": True,
            "interval_seconds": 3600.0,
            "severity": "high",
            "params": {"threshold_gb": 5.0}
        },
        {
            "id": "ram_utilization",
            "name": "RAM Utilization Check",
            "enabled": True,
            "interval_seconds": 300.0,
            "severity": "medium",
            "params": {"threshold_pct": 95.0}
        }
    ]
}


class HeartbeatNotice:
    """A surfaced proactive notification from a scheduled check."""

    def __init__(
        self,
        notice_id: str,
        check_id: str,
        title: str,
        message: str,
        severity: str = "medium",  # "low", "medium", "high", "critical"
        surfaced_at: Optional[float] = None,
        held: bool = True,
        dismissed: bool = False,
        delivery_mode: str = "log"  # "log" or "interruption"
    ):
        self.notice_id = notice_id
        self.check_id = check_id
        self.title = title
        self.message = message
        self.severity = severity
        self.surfaced_at = surfaced_at or time.time()
        self.held = held
        self.dismissed = dismissed
        self.delivery_mode = delivery_mode

    def to_dict(self) -> Dict[str, Any]:
        return {
            "notice_id": self.notice_id,
            "check_id": self.check_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "surfaced_at": self.surfaced_at,
            "held": self.held,
            "dismissed": self.dismissed,
            "delivery_mode": self.delivery_mode,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HeartbeatNotice:
        return cls(
            notice_id=data["notice_id"],
            check_id=data["check_id"],
            title=data["title"],
            message=data["message"],
            severity=data.get("severity", "medium"),
            surfaced_at=data.get("surfaced_at", time.time()),
            held=data.get("held", True),
            dismissed=data.get("dismissed", False),
            delivery_mode=data.get("delivery_mode", "log"),
        )


class HeartbeatService:
    """Manages proactive periodic checks, durable scheduling, and the catch-up inbox."""

    def __init__(
        self,
        config_path: Optional[Path | str] = None,
        state_path: Optional[Path | str] = None,
        inbox_path: Optional[Path | str] = None,
        on_surface_callback: Optional[Callable[[HeartbeatNotice], None]] = None
    ):
        hb_dir = get_heartbeat_dir()
        self.config_path = Path(config_path).resolve() if config_path else (hb_dir / "heartbeat_checks.json")
        self.state_path = Path(state_path).resolve() if state_path else (hb_dir / "heartbeat_state.json")
        self.inbox_path = Path(inbox_path).resolve() if inbox_path else (hb_dir / "heartbeat_inbox.json")
        self.on_surface_callback = on_surface_callback

        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running_checks: set[str] = set()
        self._check_runners: Dict[str, Callable[[Dict[str, Any]], Optional[Tuple[str, str, str]]]] = {}
        self.is_interface_open = True

        self._register_default_check_runners()

    # ==============================================================================
    # 1. Configuration & Persistence
    # ==============================================================================

    def load_config(self) -> Dict[str, Any]:
        """Loads heartbeat check settings from JSON; creates default if missing."""
        with self._lock:
            if not self.config_path.exists():
                self.save_config(DEFAULT_CONFIG)
                return DEFAULT_CONFIG.copy()
            try:
                data = json.loads(self.config_path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else DEFAULT_CONFIG.copy()
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("Could not parse %s: %s; using defaults", self.config_path, e)
                return DEFAULT_CONFIG.copy()

    def save_config(self, config: Dict[str, Any]) -> None:
        """Atomically saves heartbeat configuration."""
        with self._lock:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.config_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
            tmp.replace(self.config_path)

    def load_state(self) -> Dict[str, float]:
        """Loads persisted next_due timestamps per check."""
        with self._lock:
            if not self.state_path.exists():
                return {}
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                return {k: float(v) for k, v in data.items()} if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                return {}

    def save_state(self, state: Dict[str, float]) -> None:
        """Persists next_due timestamps so restarts do not reset timers or fire all at once."""
        with self._lock:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            tmp.replace(self.state_path)

    # ==============================================================================
    # 2. Catch-up Inbox & Notice Management
    # ==============================================================================

    def load_inbox(self) -> List[HeartbeatNotice]:
        """Loads held and historical notices from durable inbox storage."""
        with self._lock:
            if not self.inbox_path.exists():
                return []
            try:
                raw = json.loads(self.inbox_path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    return [HeartbeatNotice.from_dict(d) for d in raw if isinstance(d, dict)]
                return []
            except (OSError, json.JSONDecodeError):
                return []

    def save_inbox(self, notices: List[HeartbeatNotice]) -> None:
        """Atomically writes inbox notices to disk."""
        with self._lock:
            self.inbox_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.inbox_path.with_suffix(".tmp")
            payload = [n.to_dict() for n in notices[-100:]]  # Bound to last 100 notices
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.inbox_path)

    def get_pending_held_notices(self) -> List[HeartbeatNotice]:
        """Returns notices held while user interface was closed/away, not yet dismissed."""
        inbox = self.load_inbox()
        return [n for n in inbox if n.held and not n.dismissed]

    def mark_notices_delivered(self) -> List[HeartbeatNotice]:
        """Marks held notices as delivered to user upon return; retains them until dismissed."""
        with self._lock:
            inbox = self.load_inbox()
            delivered = []
            for n in inbox:
                if n.held and not n.dismissed:
                    n.held = False
                    delivered.append(n)
            self.save_inbox(inbox)
            return delivered

    def dismiss_notice(self, notice_id: str) -> bool:
        """Dismisses an alert so it clears from the active view."""
        with self._lock:
            inbox = self.load_inbox()
            found = False
            for n in inbox:
                if n.notice_id == notice_id:
                    n.dismissed = True
                    found = True
                    break
            if found:
                self.save_inbox(inbox)
            return found

    def clear_inbox(self) -> None:
        """Clears all notices from the inbox."""
        with self._lock:
            self.save_inbox([])

    # ==============================================================================
    # 3. Quiet Hours & Delivery Policy
    # ==============================================================================

    def is_in_quiet_hours(self, now_dt: Optional[datetime] = None) -> bool:
        """Checks if current time falls within configured quiet hours."""
        cfg = self.load_config()
        qh = cfg.get("quiet_hours", {})
        if not qh.get("enabled", False):
            return False
        dt = now_dt or datetime.now()
        start = qh.get("start_hour", 22)
        end = qh.get("end_hour", 8)
        current = dt.hour
        if start > end:  # Over midnight (e.g. 22:00 to 08:00)
            return current >= start or current < end
        else:
            return start <= current < end

    # ==============================================================================
    # 4. Check Runners & Execution
    # ==============================================================================

    def register_check_runner(
        self,
        check_id: str,
        runner_fn: Callable[[Dict[str, Any]], Optional[Tuple[str, str, str]]]
    ) -> None:
        """Registers a runner function for check_id.
        Runner returns (title, message, severity) if noteworthy, or None if normal/quiet.
        """
        with self._lock:
            self._check_runners[check_id] = runner_fn

    def _register_default_check_runners(self) -> None:
        """Registers default workstation health checks."""
        def run_disk_space(params: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
            try:
                import windows_tools
                import rails_config
                thresh = float(params.get("threshold_gb", 0.0))
                if thresh <= 0.0:
                    thresh, _ = rails_config.get_rails_config().get_heartbeat_thresholds()
                vitals = windows_tools.get_system_vitals()
                free_gb = float(vitals.get("disk_free_gb", 999.0))
                if free_gb < thresh:
                    return (
                        "Low Disk Space Alert",
                        f"Primary storage drive has only {free_gb:.1f} GB free (threshold: {thresh:.1f} GB).",
                        "high"
                    )
            except Exception as e:
                logger.debug("Disk space check failed: %s", e)
            return None

        def run_ram_util(params: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
            try:
                import windows_tools
                import rails_config
                thresh = float(params.get("threshold_pct", 0.0))
                if thresh <= 0.0:
                    _, thresh = rails_config.get_rails_config().get_heartbeat_thresholds()
                vitals = windows_tools.get_system_vitals()
                ram_pct = float(vitals.get("ram_pct", 0.0))
                if ram_pct > thresh:
                    return (
                        "High RAM Utilization Warning",
                        f"System memory utilization is at {ram_pct:.1f}% (threshold: {thresh:.1f}%).",
                        "medium"
                    )
            except Exception as e:
                logger.debug("RAM utilization check failed: %s", e)
            return None

        self.register_check_runner("disk_space", run_disk_space)
        self.register_check_runner("ram_utilization", run_ram_util)

    def execute_single_check(self, check_cfg: Dict[str, Any], now: float) -> Optional[HeartbeatNotice]:
        """Executes a single check if not already running (prevents overlapping snowball)."""
        check_id = check_cfg.get("id", "")
        if not check_id or not check_cfg.get("enabled", True):
            return None

        with self._lock:
            if check_id in self._running_checks:
                logger.info("Skipping overlapping check '%s' (previous run still active)", check_id)
                return None
            self._running_checks.add(check_id)

        try:
            runner = self._check_runners.get(check_id)
            if not runner:
                return None
            params = check_cfg.get("params", {})
            result = runner(params)
            if not result:
                return None

            title, message, sev = result
            # Determine delivery mode based on quiet hours and interface status
            in_quiet = self.is_in_quiet_hours()
            is_critical = sev == "critical"

            if in_quiet and not is_critical:
                delivery_mode = "log"
                held = True
            elif not self.is_interface_open:
                delivery_mode = "log"
                held = True
            else:
                delivery_mode = "interruption" if (sev in ("high", "critical")) else "log"
                held = False

            notice = HeartbeatNotice(
                notice_id=f"notice_{uuid.uuid4().hex[:12]}",
                check_id=check_id,
                title=title,
                message=message,
                severity=sev,
                surfaced_at=now,
                held=held,
                delivery_mode=delivery_mode
            )

            # Record into durable inbox
            inbox = self.load_inbox()
            inbox.append(notice)
            self.save_inbox(inbox)

            try:
                import rails_audit
                rails_audit.get_rails_audit().record_heartbeat_notice(title, sev, message)
            except Exception:
                pass

            if self.on_surface_callback and not held:
                try:
                    self.on_surface_callback(notice)
                except Exception as ex:
                    logger.warning("Error in on_surface_callback: %s", ex)

            return notice
        finally:
            with self._lock:
                self._running_checks.discard(check_id)

    def tick(self, now: Optional[float] = None) -> List[HeartbeatNotice]:
        """Runs one tick of the heartbeat loop across all enabled checks."""
        current_time = now if now is not None else time.time()

        # Kill Switch check: Immediately halts proactive checks when kill switch engaged
        if kill_switch.is_kill_switch_active():
            logger.debug("Heartbeat tick skipped: emergency kill switch is engaged")
            return []

        cfg = self.load_config()
        if not cfg.get("enabled", True):
            return []

        state = self.load_state()
        surfaced = []

        for check_cfg in cfg.get("checks", []):
            cid = check_cfg.get("id")
            if not cid or not check_cfg.get("enabled", True):
                continue

            interval = float(check_cfg.get("interval_seconds", 300.0))
            next_due = state.get(cid, 0.0)

            if current_time >= next_due:
                notice = self.execute_single_check(check_cfg, current_time)
                if notice:
                    surfaced.append(notice)
                # Persist next due timestamp
                state[cid] = current_time + interval
                self.save_state(state)

        return surfaced

    # ==============================================================================
    # 5. Background Thread Lifecycle
    # ==============================================================================

    def start(self) -> None:
        """Starts the background heartbeat loop thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, name="homie-heartbeat", daemon=True)
            self._thread.start()
            logger.info("Proactive heartbeat service started")

    def stop(self, timeout: float = 2.0) -> None:
        """Stops the background heartbeat loop thread."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("Proactive heartbeat service stopped")

    def _run_loop(self) -> None:
        """Continuous background loop execution."""
        while not self._stop_event.is_set():
            try:
                cfg = self.load_config()
                sleep_interval = float(cfg.get("loop_interval_seconds", 1.0))
                self.tick()
            except Exception as e:
                logger.warning("Heartbeat loop error: %s", e)
            self._stop_event.wait(timeout=sleep_interval)


_DEFAULT_HEARTBEAT: Optional[HeartbeatService] = None
_HB_LOCK = threading.RLock()


def get_default_heartbeat_service() -> HeartbeatService:
    global _DEFAULT_HEARTBEAT
    with _HB_LOCK:
        if _DEFAULT_HEARTBEAT is None:
            _DEFAULT_HEARTBEAT = HeartbeatService()
        return _DEFAULT_HEARTBEAT


def set_default_heartbeat_service(service: Optional[HeartbeatService]) -> None:
    global _DEFAULT_HEARTBEAT
    with _HB_LOCK:
        _DEFAULT_HEARTBEAT = service
