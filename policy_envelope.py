"""policy_envelope.py - Batch 19C: Dynamic Workstation Policy Envelope.

Solves human approval fatigue by allowing mobile-signed bounded execution envelopes:
  - Canonical Envelope Fields:
      target process image paths, allowed action types, step budget, keystroke cap,
      expiry, and taint_epoch.
  - Phone Signing:
      Cryptographically signed challenge bound to canonical envelope fields.
  - Strict Hard-Denial Enforcement:
      Actions outside the envelope, steps exceeding budget, or keystrokes exceeding cap
      are HARD DENIED (never silently prompted or permitted).
      Envelopes cannot be widened mid-run.
      Taint epoch mismatch immediately invalidates envelope.
  - Non-Bypassable High-Risk Controls:
      High-risk destructive/financial operations (Send, Delete, Pay, Submit, Install)
      ALWAYS require per-step approval even inside an approved envelope.
"""

import os
import sys
import time
import json
import hmac
import hashlib
import logging
from typing import List, Dict, Any, Optional, Tuple, Set

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import agent_audit_ledger

logger = logging.getLogger("homie.envelope")

# Actions that ALWAYS require per-step explicit human step-up even inside an envelope
HIGH_RISK_PER_STEP_CLASSES: Set[str] = {
    "send", "delete", "pay", "submit", "install",
    "homie_execute_cmd", "homie_delete_file"
}


class PolicyEnvelope:
    """Represents a bounded workstation policy envelope signed cryptographically on phone."""

    def __init__(
        self,
        envelope_id: str,
        allowed_process_images: List[str],
        allowed_action_types: List[str],
        step_budget: int,
        keystroke_cap: int,
        expiry: float,
        taint_epoch: int,
        device_id: str = "primary_phone",
        signature: Optional[str] = None
    ):
        self.envelope_id = envelope_id
        self.allowed_process_images = [p.lower() for p in allowed_process_images]
        self.allowed_action_types = list(allowed_action_types)
        self.step_budget = step_budget
        self.keystroke_cap = keystroke_cap
        self.expiry = expiry
        self.taint_epoch = taint_epoch
        self.device_id = device_id
        self.signature = signature

        # Runtime consumption counters (cannot be reset or widened)
        self.steps_consumed = 0
        self.keystrokes_consumed = 0
        self.is_active = False

    def compute_canonical_hash(self) -> str:
        """Computes deterministic canonical hash of the envelope boundary."""
        imgs = ",".join(sorted(self.allowed_process_images))
        acts = ",".join(sorted(self.allowed_action_types))
        raw = f"{self.envelope_id}|{imgs}|{acts}|{self.step_budget}|{self.keystroke_cap}|{int(self.expiry)}|{self.taint_epoch}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def generate_phone_challenge(self) -> Dict[str, Any]:
        """Creates phone-facing challenge payload for signing the envelope."""
        c_hash = self.compute_canonical_hash()
        canonical_prompt = (
            f"Workstation Policy Envelope Authorization:\n"
            f"• Target Apps: {', '.join(self.allowed_process_images) or 'Any'}\n"
            f"• Action Types: {', '.join(self.allowed_action_types)}\n"
            f"• Step Budget: {self.step_budget} steps\n"
            f"• Keystroke Cap: {self.keystroke_cap} chars\n"
            f"• Valid for: {int(self.expiry - time.time())}s\n"
            f"• Taint Epoch: {self.taint_epoch}"
        )
        return {
            "envelope_id": self.envelope_id,
            "canonical_hash": c_hash,
            "canonical_prompt": canonical_prompt,
            "step_budget": self.step_budget,
            "keystroke_cap": self.keystroke_cap,
            "expiry": self.expiry,
            "device_id": self.device_id
        }

    def activate_with_signature(self, signature: str, device_key_override: Optional[str] = None) -> Tuple[bool, str]:
        """Activates the envelope after validating mobile device HMAC-SHA256 signature."""
        now = time.time()
        if now > self.expiry:
            return False, "Envelope expired before activation"

        dev_key = device_key_override or phone_approval_portal.get_or_create_device_public_key(self.device_id)
        expected_sig = phone_approval_portal.compute_device_signature(self.compute_canonical_hash(), dev_key)

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Envelope signature invalid or tampered"

        self.signature = signature
        self.is_active = True
        logger.info("Policy envelope %s activated by device %s", self.envelope_id, self.device_id)
        return True, "Envelope successfully activated"

    def check_and_consume(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_process_image: Optional[str],
        current_taint_epoch: int
    ) -> Tuple[bool, str]:
        """Enforces envelope boundary:
        - Must be active
        - Current time <= expiry
        - current_taint_epoch == envelope.taint_epoch
        - tool_name in allowed_action_types
        - target process image in allowed_process_images
        - High-risk operations require separate per-step approval
        - step_budget and keystroke_cap not exceeded
        """
        if not self.is_active:
            return False, "DENY: Envelope is not active"

        now = time.time()
        if now > self.expiry:
            self.is_active = False
            return False, "DENY: Envelope has expired"

        if current_taint_epoch != self.taint_epoch:
            self.is_active = False
            return False, f"DENY: Taint epoch mismatch (envelope={self.taint_epoch}, current={current_taint_epoch})"

        # Check action type
        if tool_name not in self.allowed_action_types:
            return False, f"DENY: Action '{tool_name}' not permitted in active envelope"

        # Check target process image
        if current_process_image:
            proc_clean = os.path.basename(current_process_image).lower()
            if proc_clean not in self.allowed_process_images:
                return False, f"DENY: Target process '{proc_clean}' not in envelope allowed list: {self.allowed_process_images}"

        # Non-bypassable high-risk class check
        for high_risk_kw in HIGH_RISK_PER_STEP_CLASSES:
            if high_risk_kw in tool_name.lower():
                return False, f"DENY: High-risk action '{tool_name}' requires per-step step-up human approval"

        # Check step budget
        if self.steps_consumed >= self.step_budget:
            return False, f"DENY: Step budget exceeded ({self.steps_consumed}/{self.step_budget})"

        # Check keystroke cap for text entry actions
        keystrokes = 0
        if "type" in tool_name.lower() or "text" in arguments:
            text = arguments.get("text", "")
            keystrokes = len(str(text))
            if self.keystrokes_consumed + keystrokes > self.keystroke_cap:
                return False, f"DENY: Keystroke cap exceeded ({self.keystrokes_consumed + keystrokes}/{self.keystroke_cap})"

        # Consume budget
        self.steps_consumed += 1
        self.keystrokes_consumed += keystrokes

        logger.info(
            "Envelope %s consumed: step %d/%d, keystrokes %d/%d",
            self.envelope_id, self.steps_consumed, self.step_budget,
            self.keystrokes_consumed, self.keystroke_cap
        )
        return True, "ALLOWED_BY_ENVELOPE"
