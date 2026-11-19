"""Helm Multi-Channel Canary Secret Monitor.
Protects against direct, encoded, and multi-step exfiltration:
- Monitors all outbound egress: tool arguments, clipboard writes, typing text, and API responses.
- Detects plaintext, Base64, Hex, and cross-call fragmented leak attempts.
- Automatically triggers emergency kill switch lockdown on detection.
"""

import os
import sys
import base64
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import kill_switch

logger = logging.getLogger("helm.canary")

DEFAULT_CANARY_TOKEN = "CANARY_SECRET_ALPHA_OMEGA_998877"

class CanaryGuard:
    def __init__(self, canary_token=DEFAULT_CANARY_TOKEN):
        self.canary_token = canary_token
        self.b64_variant = base64.b64encode(canary_token.encode("utf-8")).decode("ascii")
        self.hex_variant = canary_token.encode("utf-8").hex()
        self.chunk_window = ""

    def inspect_egress(self, payload):
        """Scans egress content across plaintext, base64, hex, and fragmented chunks."""
        if not payload:
            return False, "Clean payload"

        text = str(payload)

        # 1. Plaintext match
        if self.canary_token in text:
            kill_switch.engage_kill_switch("Canary leak detected: Plaintext match")
            return True, "LEAK_DETECTED: Plaintext canary token matched"

        # 2. Base64 variant match
        if self.b64_variant in text:
            kill_switch.engage_kill_switch("Canary leak detected: Base64 variant match")
            return True, "LEAK_DETECTED: Base64 encoded canary token matched"

        # 3. Hex variant match
        if self.hex_variant in text.lower():
            kill_switch.engage_kill_switch("Canary leak detected: Hex variant match")
            return True, "LEAK_DETECTED: Hex encoded canary token matched"

        # 4. Sliding window chunked leak detection
        self.chunk_window = (self.chunk_window + text)[-200:]
        if self.canary_token in self.chunk_window or self.b64_variant in self.chunk_window:
            kill_switch.engage_kill_switch("Canary leak detected: Fragmented chunk match")
            return True, "LEAK_DETECTED: Fragmented canary token matched across calls"

        return False, "Clean payload"

    def reset(self):
        self.chunk_window = ""

# Global instance
_guard = CanaryGuard()

def inspect_egress_payload(payload):
    return _guard.inspect_egress(payload)

def reset_guard():
    _guard.reset()
