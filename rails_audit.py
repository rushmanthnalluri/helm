"""rails_audit.py - Tier 6 Visible Audit Trail and Running Cost / Token Tally.

Maintains:
1. A plain inspectable audit log (homie_audit.log) recording:
   - Tool execution events with arguments and outcomes.
   - Heartbeat alerts and notices surfaced.
   - Confirmation requests, approvals, and denials.
2. A running tally of model tokens and cumulative financial cost (in USD)
   to ensure runaway loops are visible immediately.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import rails_config

logger = logging.getLogger("homie.rails_audit")


def get_audit_dir() -> Path:
    base = os.environ.get("HOMIE_DIR") or (Path.home() / ".config" / "homie")
    return Path(base).resolve()


class RailsAuditTracker:
    """Manages audit logging and running cost / token tracking."""

    def __init__(self, log_path: Optional[Path | str] = None, state_path: Optional[Path | str] = None):
        audit_dir = get_audit_dir()
        self.log_path = Path(log_path).resolve() if log_path else (audit_dir / "homie_audit.log")
        self.state_path = Path(state_path).resolve() if state_path else (audit_dir / "homie_cost_state.json")
        self._lock = threading.RLock()
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_cost_usd = 0.0
        self._load_state()

    def _load_state(self) -> None:
        with self._lock:
            if not self.state_path.exists():
                return
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._total_input_tokens = int(data.get("total_input_tokens", 0))
                    self._total_output_tokens = int(data.get("total_output_tokens", 0))
                    self._total_cost_usd = float(data.get("total_cost_usd", 0.0))
            except Exception as e:
                logger.warning("Could not read cost state: %s", e)

    def _save_state(self) -> None:
        with self._lock:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            data = {
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "total_cost_usd": round(self._total_cost_usd, 6),
                "updated_at": time.time(),
            }
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.state_path)

    def append_audit_entry(self, category: str, event: str, details: Dict[str, Any]) -> None:
        """Appends an event to the human-inspectable audit log."""
        with self._lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "epoch": time.time(),
                "category": category,
                "event": event,
                "details": details,
            }
            line = json.dumps(entry) + "\n"
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)

    def record_model_usage(
        self, input_tokens: int, output_tokens: int, model_name: str = "default"
    ) -> Dict[str, Any]:
        """Calculates turn cost and adds to running tally."""
        with self._lock:
            cfg = rails_config.get_rails_config()
            in_rate, out_rate = cfg.get_cost_rates()
            turn_cost = ((input_tokens / 1_000_000.0) * in_rate) + ((output_tokens / 1_000_000.0) * out_rate)

            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            self._total_cost_usd += turn_cost
            self._save_state()

            self.append_audit_entry(
                category="llm_usage",
                event="model_turn",
                details={
                    "model": model_name,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "turn_cost_usd": round(turn_cost, 6),
                    "running_cost_usd": round(self._total_cost_usd, 6),
                },
            )

            return {
                "turn_cost_usd": round(turn_cost, 6),
                "total_cost_usd": round(self._total_cost_usd, 6),
                "total_tokens": self._total_input_tokens + self._total_output_tokens,
            }

    def record_tool_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        caller_id: str,
        ok: bool,
        latency_ms: float,
        requires_confirmation: bool = False,
        confirmed: bool = False,
    ) -> None:
        """Records tool execution into audit log."""
        self.append_audit_entry(
            category="tool_execution",
            event="tool_call",
            details={
                "tool_name": tool_name,
                "arguments": arguments,
                "caller_id": caller_id,
                "ok": ok,
                "latency_ms": latency_ms,
                "requires_confirmation": requires_confirmation,
                "confirmed": confirmed,
            },
        )

    def record_heartbeat_notice(self, notice_title: str, severity: str, message: str) -> None:
        """Records proactive notice into audit log."""
        self.append_audit_entry(
            category="heartbeat",
            event="notice_surfaced",
            details={"title": notice_title, "severity": severity, "message": message},
        )

    def record_confirmation_event(self, request_id: str, tool_name: str, action: str, details: str = "") -> None:
        """Records confirmation gate events (CREATED, APPROVED, DENIED, CONSUMED)."""
        self.append_audit_entry(
            category="confirmation_gate",
            event=f"confirmation_{action.lower()}",
            details={"request_id": request_id, "tool_name": tool_name, "action": action, "info": details},
        )

    def get_cost_summary(self) -> Dict[str, Any]:
        """Returns snapshot of cumulative token and cost metrics."""
        with self._lock:
            return {
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "total_tokens": self._total_input_tokens + self._total_output_tokens,
                "total_cost_usd": round(self._total_cost_usd, 6),
            }


_GLOBAL_AUDIT: Optional[RailsAuditTracker] = None
_AUDIT_LOCK = threading.RLock()


def get_rails_audit(log_path: Optional[Path | str] = None) -> RailsAuditTracker:
    global _GLOBAL_AUDIT
    with _AUDIT_LOCK:
        if _GLOBAL_AUDIT is None or log_path is not None:
            _GLOBAL_AUDIT = RailsAuditTracker(log_path)
        return _GLOBAL_AUDIT
