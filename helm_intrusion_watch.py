"""helm_intrusion_watch.py - Intrusion Detection & Multi-Channel Security Telemetry Mirror.

Detects unauthorized probing and door-rattling attempts:
- API Tokens: 5 wrong or missing tokens within 5 minutes (indicates unauthorized local process).
- Telegram Strangers: 3 unauthorized messages from an unpaired account within 10 minutes.
- Multi-Channel Alert: Emits desktop toast, Telegram owner alert, and HMAC audit ledger record.
- 30-Minute Quiet Window: Prevents attackers from weaponizing alerts into notification spam.
"""

from __future__ import annotations

import time
import logging
from collections import deque
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger("helm.intrusion")

THRESHOLDS: dict[str, tuple[int, float]] = {
    "api_token": (5, 300.0),            # 5 failures in 5 min
    "telegram_stranger": (3, 600.0),    # 3 messages from unknown in 10 min
}

QUIET_SECONDS = 30 * 60  # 30-minute cooldown after triggering an alert


class IntrusionWatch:
    def __init__(self, now_fn: Callable[[], float] = time.monotonic):
        self.now_fn = now_fn
        self._seen: dict[str, deque[float]] = {k: deque(maxlen=n) for k, (n, _) in THRESHOLDS.items()}
        self._quiet_until: dict[str, float] = {}
        self.alert_count = 0

    def note_attempt(self, kind: str, who: str = "") -> Optional[str]:
        """Records one refused attempt. Returns alert string if threshold crossed, else None."""
        limit = THRESHOLDS.get(kind)
        if not limit:
            return None

        count, window_sec = limit
        now = self.now_fn()

        # Check quiet window
        if now < self._quiet_until.get(kind, 0.0):
            return None

        seen = self._seen[kind]
        seen.append(now)

        if len(seen) < count or (now - seen[0]) > window_sec:
            return None

        # Threshold crossed!
        self._quiet_until[kind] = now + QUIET_SECONDS
        seen.clear()
        self.alert_count += 1

        alert_msg = self._format_alert(kind, count, int(window_sec // 60), who)
        logger.warning("INTRUSION_ALERT: %s (who=%s)", alert_msg, who)

        # Dispatch multi-channel notification
        self._dispatch_alert(kind, alert_msg, who)
        return alert_msg

    def _format_alert(self, kind: str, count: int, minutes: int, who: str) -> str:
        clean_who = "".join(c for c in str(who) if c.isprintable())[:40] or "Unknown"
        if kind == "api_token":
            return (
                f"🚨 Security Alert: {count} local requests used an invalid or missing API token within "
                f"{minutes} minutes. Potential unauthorized process probing Helm on this PC."
            )
        elif kind == "telegram_stranger":
            return (
                f"🚨 Security Alert: {count} messages received from unpaired Telegram user ({clean_who}) "
                f"within {minutes} minutes. Unauthorized remote access rejected."
            )
        return f"🚨 Security Alert: {count} unauthorized attempts of type '{kind}' detected."

    def _dispatch_alert(self, kind: str, text: str, who: str) -> None:
        # 1. Desktop Notification
        try:
            import tray_hud
            tray_hud.post_hud_notification("🛡️ Security Intrusion Warning", text)
        except Exception:
            pass

        # 2. Telegram Companion Alert to paired owner
        try:
            import telegram_bridge
            tb = telegram_bridge.get_telegram_bridge()
            if tb and getattr(tb, "paired_chat_id", None):
                tb.send_message(tb.paired_chat_id, text)
        except Exception:
            pass

        # 3. Cryptographic HMAC-SHA256 Audit Ledger
        try:
            import agent_audit_ledger
            agent_audit_ledger.record_agent_action(
                caller_id="intrusion_watch",
                tool_name=f"alert_{kind}",
                tier="SECURITY_GATE",
                arguments={"kind": kind, "who": who, "alert": text},
                decision="ALERT_DISPATCHED"
            )
        except Exception:
            pass


_GLOBAL_INTRUSION_WATCH: Optional[IntrusionWatch] = None


def get_intrusion_watch() -> IntrusionWatch:
    global _GLOBAL_INTRUSION_WATCH
    if _GLOBAL_INTRUSION_WATCH is None:
        _GLOBAL_INTRUSION_WATCH = IntrusionWatch()
    return _GLOBAL_INTRUSION_WATCH


def note_unauthorized_attempt(kind: str, who: str = "") -> Optional[str]:
    """Helper function to record an unauthorized attempt across any ingress channel."""
    return get_intrusion_watch().note_attempt(kind, who)
