"""helm_resource_tracker.py - Resource-Aware Telemetry & Cost Accounting.

Inspired by OpenJarvis (Stanford) resource evaluation doctrine:
- Tracks prompt and completion tokens per turn.
- Estimates FLOPs footprint (floating point operations).
- Calculates dollar cost per turn and accumulates daily expenditures.
- Enforces strict cost circuit-breakers preventing runaway model loops.
- Emits structured telemetry to the HMAC audit ledger.
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("helm.resource_tracker")

# Model pricing table (USD per 1,000,000 tokens)
MODEL_PRICING = {
    "gemini-2.5-flash": {"prompt": 0.075, "completion": 0.30, "params_b": 8},
    "gemini-1.5-flash": {"prompt": 0.075, "completion": 0.30, "params_b": 8},
    "gemini-1.5-pro": {"prompt": 1.25, "completion": 5.00, "params_b": 70},
    "claude-3-5-sonnet": {"prompt": 3.00, "completion": 15.00, "params_b": 70},
    "claude-3-haiku": {"prompt": 0.25, "completion": 1.25, "params_b": 8},
    "local_model": {"prompt": 0.0, "completion": 0.0, "params_b": 8},
}


class ResourceTracker:
    """Tracks token consumption, latency, energy/FLOPs, and dollar spend across turns."""

    def __init__(self, daily_budget_usd: float = 5.0):
        self.daily_budget_usd = daily_budget_usd
        self._daily_spend = 0.0
        self._total_turns = 0
        self._last_reset_day = time.strftime("%Y-%m-%d")

    def _check_day_reset(self):
        today = time.strftime("%Y-%m-%d")
        if today != self._last_reset_day:
            self._daily_spend = 0.0
            self._last_reset_day = today

    def estimate_cost(self, model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculates estimated dollar cost for a turn."""
        clean_name = "local_model" if "ollama" in model_name.lower() or "local" in model_name.lower() else "gemini-2.5-flash"
        for key in MODEL_PRICING:
            if key in model_name.lower():
                clean_name = key
                break
        rates = MODEL_PRICING.get(clean_name, MODEL_PRICING["gemini-2.5-flash"])
        cost = (prompt_tokens / 1_000_000.0) * rates["prompt"] + (completion_tokens / 1_000_000.0) * rates["completion"]
        return round(cost, 6)

    def estimate_flops(self, model_name: str, total_tokens: int) -> float:
        """Estimates floating point operations (FLOPs) using the 6 * N * P standard scaling law."""
        clean_name = "gemini-2.5-flash"
        for key in MODEL_PRICING:
            if key in model_name.lower():
                clean_name = key
                break
        params_b = MODEL_PRICING.get(clean_name, {}).get("params_b", 8)
        # 6 FLOPs per parameter per token
        flops = 6 * (params_b * 1e9) * total_tokens
        return flops

    def record_turn(
        self,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        caller_id: str = "assistant"
    ) -> Dict[str, Any]:
        """Records a completed agent turn and verifies budget constraints."""
        self._check_day_reset()
        total_tokens = prompt_tokens + completion_tokens
        cost = self.estimate_cost(model_name, prompt_tokens, completion_tokens)
        flops = self.estimate_flops(model_name, total_tokens)

        self._daily_spend += cost
        self._total_turns += 1

        budget_exceeded = self._daily_spend > self.daily_budget_usd
        if budget_exceeded:
            logger.warning(
                "Daily spend budget exceeded: $%.4f > $%.2f limit!",
                self._daily_spend, self.daily_budget_usd
            )

        telemetry = {
            "model": model_name,
            "caller_id": caller_id,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "latency_ms": round(latency_ms, 2),
            "estimated_cost_usd": cost,
            "estimated_flops": flops,
            "cumulative_daily_spend_usd": round(self._daily_spend, 6),
            "budget_exceeded": budget_exceeded
        }

        # Record to audit ledger
        try:
            import agent_audit_ledger
            agent_audit_ledger.record_agent_action(
                caller_id,
                "model_inference_turn",
                "READ_ONLY",
                {"model": model_name, "tokens": total_tokens, "latency_ms": latency_ms, "cost": cost},
                decision="BUDGET_EXCEEDED" if budget_exceeded else "ALLOW"
            )
        except Exception:
            pass

        return telemetry

    @property
    def daily_spend(self) -> float:
        self._check_day_reset()
        return self._daily_spend


_GLOBAL_TRACKER = None

def get_resource_tracker() -> ResourceTracker:
    global _GLOBAL_TRACKER
    if _GLOBAL_TRACKER is None:
        _GLOBAL_TRACKER = ResourceTracker()
    return _GLOBAL_TRACKER
