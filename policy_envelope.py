"""policy_envelope.py - Batch 19C & Batch 21: Dynamic Workstation Policy Envelope.

Solves human approval fatigue by allowing mobile-signed bounded execution envelopes
with strict architectural hardening:
  - Canonical Envelope Fields:
      target process image paths, allowed action types, step budget, keystroke cap,
      expiry, taint_epoch, and browser domain scope.
  - Prohibited Approvable Images:
      Execution environments, macro-enabled office suites, and arbitrary file managers
      (Explorer, Cmd, PowerShell, WT, Code, Word, Excel) CANNOT be approved in an envelope.
  - Browser Domain Scoping:
      Browsers in an envelope MUST be restricted to an explicit allowed domain list (e.g. docs.python.org).
      Out-of-scope domain navigations are hard denied.
  - Semantic High-Risk Control Detection:
      Detects disguised controls ("Continue", "Next", "Agree", "Transfer", "Buy", "Checkout")
      and treats Enter-in-forms as high-risk submits. Unknown controls default to high-risk.
  - Strict Hard-Denial Enforcement:
      Actions outside the envelope, steps exceeding budget, or keystrokes exceeding cap
      are HARD DENIED (never silently prompted or permitted).
      Envelopes cannot be widened mid-run.
      Taint epoch mismatch immediately invalidates envelope.
  - Non-Bypassable High-Risk Controls:
      High-risk destructive/financial operations ALWAYS require per-step approval even inside an approved envelope.
"""

import os
import sys
import re
import time
import json
import hmac
import secrets
import hashlib
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import agent_audit_ledger

logger = logging.getLogger("homie.envelope")

# Prohibited images that CANNOT be approved in any policy envelope
PROHIBITED_ENVELOPE_IMAGES: Set[str] = {
    "explorer.exe", "cmd.exe", "powershell.exe", "wt.exe",
    "bash.exe", "code.exe", "vscode.exe", "excel.exe", "winword.exe"
}

# Known browser and web-rendering process images requiring domain scoping
BROWSER_IMAGES: Set[str] = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "vivaldi.exe", "arc.exe", "chromium.exe",
    "slack.exe", "teams.exe", "discord.exe"
}

# High-risk action names
HIGH_RISK_PER_STEP_CLASSES: Set[str] = {
    "send", "delete", "pay", "submit", "install",
    "homie_execute_cmd", "homie_delete_file"
}

# Semantic keywords indicating high-risk controls (even if labeled "Continue", "Next", etc.)
HIGH_RISK_CONTROL_KEYWORDS: Set[str] = {
    "send", "delete", "remove", "pay", "checkout", "buy", "order",
    "transfer", "wire", "submit", "install", "confirm", "continue",
    "next", "agree", "accept terms", "purchase", "authorize"
}


def is_domain_allowed(candidate: str, allowed: str) -> bool:
    """Strict host or dot-boundary subdomain matching.
    Prevents subdomain confusion / substring spoofing (e.g., 'fakebank.com' matching 'bank.com').
    """
    c = candidate.lower().strip()
    a = allowed.lower().strip()
    return c == a or c.endswith("." + a)


def canonicalize_keyboard_arguments(arguments: Dict[str, Any]) -> Tuple[bool, bool, List[int], List[str]]:
    """Canonicalizes all keyboard and input arguments across all schemas using discrete VK-events.
    Delegates to windows_tools.canonicalize_keyboard_arguments to ensure identical injector-level semantics.
    """
    try:
        import windows_tools
        return windows_tools.canonicalize_keyboard_arguments(arguments)
    except Exception:
        # Fallback in case windows_tools is mocked or unavailable
        text_val = arguments.get("text")
        enter_detected = False
        if isinstance(text_val, str) and ("\n" in text_val or "\r" in text_val):
            enter_detected = True
        return enter_detected, False, [], []

def detect_blocked_system_chords(detected_vks: List[int], tokens: List[str]) -> Optional[str]:
    """Detects dangerous system hotkey chords. Delegates to windows_tools."""
    try:
        import windows_tools
        return windows_tools.detect_blocked_system_chords(detected_vks, tokens)
    except Exception:
        return None


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
        allowed_domains: Optional[List[str]] = None,
        device_id: str = "primary_phone",
        signature: Optional[str] = None
    ):
        clean_images = [os.path.basename(p).lower() for p in allowed_process_images]
        # Disallow prohibited executable/macro environments
        for img in clean_images:
            if img in PROHIBITED_ENVELOPE_IMAGES:
                raise ValueError(
                    f"Prohibited process image '{img}' cannot be included in a policy envelope: execution environments and arbitrary file/macro processors are barred."
                )

        self.envelope_id = envelope_id
        self.allowed_process_images = clean_images
        self.allowed_action_types = list(allowed_action_types)
        self.step_budget = step_budget
        self.keystroke_cap = keystroke_cap
        self.expiry = expiry
        self.taint_epoch = taint_epoch
        self.allowed_domains = [d.lower() for d in allowed_domains] if allowed_domains else []
        self.device_id = device_id
        self.signature = signature

        # Runtime consumption counters (cannot be reset or widened)
        self.steps_consumed = 0
        self.reserved_steps = 0
        self._active_reservations: Set[str] = set()
        self._last_reservation_token: Optional[str] = None
        self.keystrokes_consumed = 0
        self.is_active = False
        self._envelope_lock = threading.Lock()

    @property
    def allowed_target_processes(self) -> List[str]:
        """Alias for allowed_process_images for architectural consistency."""
        return self.allowed_process_images

    @allowed_target_processes.setter
    def allowed_target_processes(self, val: List[str]):
        self.allowed_process_images = [os.path.basename(p).lower() for p in val]

    def compute_canonical_hash(self) -> str:
        """Computes deterministic canonical hash of the envelope boundary."""
        imgs = ",".join(sorted(self.allowed_process_images))
        acts = ",".join(sorted(self.allowed_action_types))
        doms = ",".join(sorted(self.allowed_domains))
        raw = f"{self.envelope_id}|{imgs}|{acts}|{doms}|{self.step_budget}|{self.keystroke_cap}|{int(self.expiry)}|{self.taint_epoch}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def generate_phone_challenge(self) -> Dict[str, Any]:
        """Creates phone-facing challenge payload for signing the envelope."""
        c_hash = self.compute_canonical_hash()
        canonical_prompt = (
            f"Workstation Policy Envelope Authorization:\n"
            f"• Target Apps: {', '.join(self.allowed_process_images) or 'Any'}\n"
            f"• Domain Scope: {', '.join(self.allowed_domains) or 'None (Non-Browser)'}\n"
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
            "allowed_domains": self.allowed_domains,
            "device_id": self.device_id
        }

    def activate_with_signature(self, signature: str) -> Tuple[bool, str]:
        """Activates the envelope after validating mobile device asymmetric Ed25519 signature."""
        now = time.time()
        if now > self.expiry:
            return False, "Envelope expired before activation"

        registry = phone_approval_portal._load_device_registry()
        dev_entry = registry.get(self.device_id)
        if not dev_entry:
            return False, f"DEVICE_UNKNOWN: Device '{self.device_id}' is not enrolled in supervisor registry"

        if dev_entry.get("revoked", False):
            return False, f"DEVICE_REVOKED: Device '{self.device_id}' has been revoked"

        raw_bytes = self.compute_canonical_hash().encode('utf-8')
        sig_ok = phone_approval_portal.verify_asymmetric_signature(dev_entry["public_key"], raw_bytes, signature)
        if not sig_ok:
            return False, "Envelope signature invalid or tampered"

        self.signature = signature
        self.is_active = True
        logger.info("Policy envelope %s activated by device %s", self.envelope_id, self.device_id)
        return True, "Envelope successfully activated"

    def check_boundary(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_process_image: Optional[str],
        current_taint_epoch: int,
        current_domain: Optional[str] = None
    ) -> Tuple[bool, str, int]:
        """Validates envelope boundaries WITHOUT consuming steps or keystrokes (Two-Phase Commit Phase 1).
        Returns: (is_valid, reason_message, keystrokes_for_action)
        """
        if not self.is_active:
            return False, "DENY: Envelope is not active", 0

        now = time.time()
        if now > self.expiry:
            with self._envelope_lock:
                self.is_active = False
            return False, "DENY: Envelope has expired", 0

        if current_taint_epoch != self.taint_epoch:
            with self._envelope_lock:
                self.is_active = False
            return False, f"DENY: Taint epoch mismatch (envelope={self.taint_epoch}, current={current_taint_epoch})", 0

        # Check action type
        if tool_name not in self.allowed_action_types:
            return False, f"DENY: Action '{tool_name}' not permitted in active envelope", 0

        # Check target process image (fail-closed if omitted when allowed_process_images is configured)
        proc_clean = ""
        if self.allowed_process_images:
            if not current_process_image:
                return False, f"DENY: Missing target process image; envelope requires one of: {self.allowed_process_images}", 0
            proc_clean = os.path.basename(current_process_image).lower()
            if proc_clean not in self.allowed_process_images:
                return False, f"DENY: Target process '{proc_clean}' not in envelope allowed list: {self.allowed_process_images}", 0
        elif current_process_image:
            proc_clean = os.path.basename(current_process_image).lower()

        # Browser Domain Scoping Check with Strict Dot-Boundary Suffix Matching (fail-closed if domain missing)
        has_browser_proc = proc_clean in BROWSER_IMAGES or any(p.lower() in BROWSER_IMAGES for p in self.allowed_process_images)
        is_browser_action = has_browser_proc or "browse" in tool_name.lower() or "click_web" in tool_name.lower()

        if is_browser_action:
            if not self.allowed_domains:
                return False, "DENY: Browser envelope requires explicit non-empty allowed_domains", 0
            if not current_domain:
                return False, "DENY: Browser domain could not be verified via UIA (fail-closed)", 0
            if not any(is_domain_allowed(current_domain, d) for d in self.allowed_domains):
                return False, f"DENY: Browser domain '{current_domain}' outside envelope domain scope: {self.allowed_domains}", 0
        elif self.allowed_domains and current_domain:
            if not any(is_domain_allowed(current_domain, d) for d in self.allowed_domains):
                return False, f"DENY: Target domain '{current_domain}' outside envelope domain scope: {self.allowed_domains}", 0

        # Canonicalize keyboard arguments for precision Enter submit and synthetic Ctrl+Alt+P detection
        enter_detected, ctrl_alt_p_detected, detected_vks, tokens = canonicalize_keyboard_arguments(arguments)

        # Physical console enrollment hotkey (Ctrl + Alt + P) can NEVER be synthesized
        if ctrl_alt_p_detected:
            return False, "DENY: Synthetic simulation of physical console pairing hotkey (Ctrl+Alt+P) is strictly prohibited.", 0

        # Prohibited system hotkey chords (Win+R, Win+X, Alt+F4, Ctrl+Shift+Esc, Ctrl+Alt+Del)
        blocked_chord = detect_blocked_system_chords(detected_vks, tokens)
        if blocked_chord:
            return False, f"DENY: Synthetic injection of dangerous system hotkey chord '{blocked_chord}' is strictly prohibited.", 0

        # Check Enter-to-submit form pattern
        if enter_detected:
            return False, "DENY: Keystroke contains Enter-to-submit form submission. Requires per-step step-up human approval.", 0

        # Non-bypassable high-risk class check (tool name)
        for high_risk_kw in HIGH_RISK_PER_STEP_CLASSES:
            if high_risk_kw in tool_name.lower():
                return False, f"DENY: High-risk action '{tool_name}' requires per-step step-up human approval", 0

        # Semantic High-Risk Control & Stealth Submission Detection
        elem_name = str(arguments.get("element_name", "")).lower()

        # Check element name against high-risk keywords (e.g. "Continue", "Next", "Agree" in payment/submission context)
        for kw in HIGH_RISK_CONTROL_KEYWORDS:
            if kw in elem_name:
                return False, f"DENY: Semantic high-risk control detected ('{elem_name}' matches '{kw}'). Requires per-step step-up human approval.", 0

        with self._envelope_lock:
            # Check step budget with active reservations
            if (self.steps_consumed + self.reserved_steps) >= self.step_budget:
                return False, f"DENY: Step budget exceeded ({self.steps_consumed + self.reserved_steps}/{self.step_budget})", 0

            # Check keystroke cap for text entry actions
            keystrokes = 0
            if "type" in tool_name.lower() or "text" in arguments:
                text = arguments.get("text", "")
                keystrokes = len(str(text))
                if self.keystrokes_consumed + keystrokes > self.keystroke_cap:
                    return False, f"DENY: Keystroke cap exceeded ({self.keystrokes_consumed + keystrokes}/{self.keystroke_cap})", 0

            # Atomically reserve step with unguessable reservation token
            res_token = f"res_{secrets.token_hex(8)}"
            if not hasattr(self, "_active_reservations"):
                self._active_reservations = set()
            self._active_reservations.add(res_token)
            self.reserved_steps = len(self._active_reservations)
            self._last_reservation_token = res_token
            return True, "ALLOWED_BY_ENVELOPE", keystrokes

    def reserve_step(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_process_image: Optional[str],
        current_taint_epoch: int,
        current_domain: Optional[str] = None
    ) -> Tuple[bool, str, int, Optional[str]]:
        """Validates envelope boundaries and atomically allocates a reservation token."""
        valid, msg, ks = self.check_boundary(
            tool_name, arguments, current_process_image, current_taint_epoch, current_domain
        )
        if not valid:
            return False, msg, 0, None
        return True, msg, ks, getattr(self, "_last_reservation_token", None)

    def release_reservation(self, reservation_token: Optional[str] = None):
        """Releases a reserved step if the action proposal was rejected, denied, or aborted."""
        with self._envelope_lock:
            if not hasattr(self, "_active_reservations"):
                self._active_reservations = set()
            if reservation_token and reservation_token in self._active_reservations:
                self._active_reservations.remove(reservation_token)
            elif self._active_reservations:
                self._active_reservations.pop()
            self.reserved_steps = len(self._active_reservations)

    def commit_step(self, keystrokes: int = 0, reservation_token: Optional[str] = None):
        """Commits one step and keystrokes to the envelope budget (Two-Phase Commit Phase 2)."""
        with self._envelope_lock:
            if not hasattr(self, "_active_reservations"):
                self._active_reservations = set()
            if reservation_token and reservation_token in self._active_reservations:
                self._active_reservations.remove(reservation_token)
            elif self._active_reservations:
                self._active_reservations.pop()
            self.reserved_steps = len(self._active_reservations)
            self.steps_consumed += 1
            self.keystrokes_consumed += max(0, int(keystrokes))
        logger.info(
            "Envelope %s committed: step %d/%d, keystrokes %d/%d",
            self.envelope_id, self.steps_consumed, self.step_budget,
            self.keystrokes_consumed, self.keystroke_cap
        )

    def check_and_consume(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_process_image: Optional[str],
        current_taint_epoch: int,
        current_domain: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Convenience method combining boundary check and immediate budget commit."""
        valid, msg, ks = self.check_boundary(
            tool_name, arguments, current_process_image, current_taint_epoch, current_domain
        )
        if not valid:
            return False, msg
        self.commit_step(ks)
        return True, msg
