"""rails_confirmation.py - Tier 6 Hard Confirmation Gate for Consequential Actions.

Enforces:
1. Hard confirmation gate: Consequential actions stop and require explicit human YES before execution.
2. Plain-English impact description stating exactly what the tool intends to do.
3. Per-action approval: Approving one action does not generalize to future calls or other actions.
4. Single-use cryptographic approval tokens: Tokens are consumed upon execution and cannot be replayed.
5. Expiration: Unconfirmed or unconsumed requests expire safely.
"""

from __future__ import annotations

import os
import json
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("homie.rails_confirmation")

TOKEN_EXPIRY_SECONDS = 300.0  # 5 minutes


def _format_impact_summary(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Produces a concise, plain-English summary of what the consequential action will do."""
    if tool_name == "homie_set_clipboard":
        text = str(arguments.get("text", ""))
        preview = text[:40] + ("..." if len(text) > 40 else "")
        return f"Will overwrite system clipboard with {len(text)} characters: {preview!r}"

    elif tool_name == "homie_launch_app":
        app = arguments.get("app_name", arguments.get("path", "unknown"))
        return f"Will launch application: {app}"

    elif tool_name == "homie_close_app":
        app = arguments.get("app_name", "unknown")
        return f"Will force close application window/process: {app}"

    elif tool_name == "homie_kill_process":
        target = arguments.get("target", arguments.get("pid", "unknown"))
        return f"Will kill process: {target}"

    elif tool_name == "homie_safe_command":
        cmd = arguments.get("command", "")
        return f"Will execute system command: {cmd}"

    elif tool_name == "homie_send_chat":
        chat_id = arguments.get("chat_id", "")
        text = str(arguments.get("text", ""))
        return f"Will send message to chat {chat_id}: {text[:50]!r}"

    elif tool_name in ("homie_agent_click", "homie_agent_type", "homie_send_hotkey", "homie_agent_mouse_move"):
        return f"Will perform automated UI interaction ({tool_name}) with parameters: {arguments}"

    # Default description
    return f"Will execute consequential tool '{tool_name}' with parameters: {arguments}"


@dataclass
class ConfirmationRequest:
    request_id: str
    tool_name: str
    arguments: Dict[str, Any]
    caller_id: str
    impact_summary: str
    created_at: float
    status: str = "PENDING"  # PENDING, APPROVED, CONSUMED, DENIED, EXPIRED
    approval_token: Optional[str] = None
    presence_challenge: Optional[str] = None
    dispatched_phone: bool = False
    dispatch_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "caller_id": self.caller_id,
            "impact_summary": self.impact_summary,
            "created_at": self.created_at,
            "status": self.status,
            "presence_challenge": self.presence_challenge,
            "dispatched_phone": self.dispatched_phone,
            "dispatch_error": self.dispatch_error,
        }


class ConfirmationGate:
    """Manages consequential action confirmations and single-use tokens."""

    def __init__(self):
        self._lock = threading.RLock()
        self._requests: Dict[str, ConfirmationRequest] = {}
        self._tokens: Dict[str, str] = {}  # token -> request_id
        self._consumed_tokens: set[str] = set()

    def create_request(
        self, tool_name: str, arguments: Dict[str, Any], caller_id: str = "assistant"
    ) -> ConfirmationRequest:
        """Creates a pending confirmation request requiring human yes.
        If a paired phone is enrolled, automatically routes challenge to phone approval portal.
        """
        with self._lock:
            req_id = f"conf_{secrets.token_hex(8)}"
            summary = _format_impact_summary(tool_name, arguments)
            req = ConfirmationRequest(
                request_id=req_id,
                tool_name=tool_name,
                arguments=arguments.copy() if isinstance(arguments, dict) else {},
                caller_id=caller_id,
                impact_summary=summary,
                created_at=time.time(),
                status="PENDING",
            )
            self._requests[req_id] = req

            # Out-of-band mobile binding: if paired phone enrolled, dispatch challenge
            try:
                import device_registry
                devices = device_registry.get_enrolled_devices()
                if devices:
                    import phone_approval_portal
                    import taint_tracker
                    primary = device_registry.get_primary_device_id() or list(devices.keys())[0]
                    current_epoch = taint_tracker.get_taint_epoch()
                    chal = phone_approval_portal.generate_approval_challenge(
                        step_up_id=req_id,
                        tool_name=tool_name,
                        arguments=arguments if isinstance(arguments, dict) else {},
                        session_id=req_id,
                        taint_epoch=current_epoch,
                        device_id=primary,
                        caller_id=caller_id,
                        ttl_seconds=300
                    )
                    req.dispatched_phone = True
                    req.impact_summary += f" [Dispatched to paired phone: seq {chal.get('challenge_seq', 1)}]"
                else:
                    # When no mobile device is paired, generate high-entropy physical presence challenge
                    req.presence_challenge = f"{secrets.randbelow(1000000):06d}"
            except Exception as disp_err:
                req.dispatch_error = str(disp_err)
                logger.error("Error evaluating device pairing or dispatching challenge for %s: %s", req_id, disp_err)

            logger.info("Created confirmation request %s for %s: %s", req_id, tool_name, summary)
            return req

    def get_request(self, request_id: str) -> Optional[ConfirmationRequest]:
        with self._lock:
            req = self._requests.get(request_id)
            if req and req.status == "PENDING" and (time.time() - req.created_at > TOKEN_EXPIRY_SECONDS):
                req.status = "EXPIRED"
            return req

    def get_pending_requests(self) -> List[ConfirmationRequest]:
        with self._lock:
            now = time.time()
            res = []
            for r in self._requests.values():
                if r.status == "PENDING":
                    if now - r.created_at > TOKEN_EXPIRY_SECONDS:
                        r.status = "EXPIRED"
                    else:
                        res.append(r)
            return res

    def confirm(
        self,
        request_id: str,
        signed_evidence: Optional[Dict[str, Any]] = None,
        presence_gesture: Optional[str] = None,
        human_caller_id: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Human explicitly confirms request. Generates a single-use execution token.
        Security Invariants:
        1. If one or more mobile devices are enrolled in device_registry:
           Confirmation STRICTLY REQUIRES a cryptographically verified signed approval blob
           from the enrolled device. Unsigned or missing signatures are unconditionally denied.
        2. If no mobile devices are enrolled:
           Confirmation requires an explicit physical presence gesture (matching ephemeral challenge code).
        3. Bot / worker callers are strictly denied.
        """
        # Strict anti-bot/anti-worker enforcement: AI agents and background workers CANNOT confirm actions
        if human_caller_id and str(human_caller_id).startswith(("worker", "agent", "ai_", "script", "bot")):
            return False, f"DENIED: Confirmation must be issued by a verified human operator, not '{human_caller_id}'.", None

        with self._lock:
            req = self.get_request(request_id)
            if not req:
                return False, f"Request '{request_id}' not found.", None
            if req.status != "PENDING":
                return False, f"Request '{request_id}' is already {req.status}.", None

            # 1. Check enrolled hardware devices
            try:
                import device_registry
                devices = device_registry.get_enrolled_devices()
            except Exception:
                devices = {}

            if devices:
                # When devices are enrolled, phone cryptographic proof is strictly required
                if not signed_evidence:
                    return False, "DENIED: Action confirmation strictly requires verified out-of-band signature from enrolled mobile device.", None

                clean_args = json.dumps(req.arguments, sort_keys=True, separators=(',', ':')) if isinstance(req.arguments, dict) else str(req.arguments)
                args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()

                verified = False
                err_detail = "Signature verification failed"

                # Path A: Verify via phone_approval_portal action approval
                try:
                    import phone_approval_portal
                    ok, msg = phone_approval_portal.verify_action_approval(
                        signed_evidence, req.tool_name, args_hash
                    )
                    if ok:
                        verified = True
                    else:
                        err_detail = msg
                except Exception as e:
                    err_detail = str(e)

                # Path B: Verify via homie_supervisor Signed Approval Blob (CHALLENGE_V3)
                if not verified:
                    try:
                        import homie_supervisor
                        import taint_tracker
                        t_epoch = taint_tracker.get_taint_epoch()
                        if homie_supervisor.verify_signed_approval_evidence(
                            signed_evidence, req.caller_id, req.tool_name, args_hash, t_epoch
                        ):
                            verified = True
                    except Exception as e:
                        err_detail = f"{err_detail}; {e}"

                if not verified:
                    return False, f"DENIED: Mobile signature verification failed: {err_detail}", None

            else:
                # No enrolled mobile device: requires physical presence gesture matching ephemeral challenge
                if not presence_gesture:
                    return False, "DENIED: No enrolled device. Physical presence challenge gesture required for confirmation.", None
                if not req.presence_challenge or not hmac.compare_digest(str(presence_gesture).strip(), str(req.presence_challenge).strip()):
                    return False, "DENIED: Invalid physical presence challenge gesture.", None

            token = f"tok_{secrets.token_hex(16)}"
            req.status = "APPROVED"
            req.approval_token = token
            self._tokens[token] = request_id

            # Align with supervisor taint step-up gate: register token with taint_tracker
            try:
                import taint_tracker
                taint_tracker.register_step_up_token(token, req.tool_name, req.arguments)
            except Exception:
                pass

            logger.info("Request %s confirmed via verified proof. Issued token %s", request_id, token)
            return True, f"Action confirmed: {req.impact_summary}", token

    def deny(self, request_id: str, reason: str = "") -> bool:
        """Human explicitly denies request."""
        with self._lock:
            req = self.get_request(request_id)
            if not req:
                return False
            req.status = "DENIED"
            logger.info("Request %s denied: %s", request_id, reason)
            return True

    def verify_and_consume_token(self, tool_name: str, approval_token: str) -> Tuple[bool, str]:
        """Atomically checks and consumes single-use approval token.
        Ensures token was issued for this specific tool and has not been used.
        """
        if not approval_token:
            return False, "Approval token is missing."

        with self._lock:
            if approval_token in self._consumed_tokens:
                return False, "Denial: Approval token has already been consumed (anti-replay violation)."

            req_id = self._tokens.get(approval_token)
            if not req_id:
                return False, "Denial: Invalid or unrecognized approval token."

            req = self._requests.get(req_id)
            if not req:
                return False, "Denial: Associated confirmation request was not found."

            if req.status != "APPROVED":
                return False, f"Denial: Request status is {req.status}, expected APPROVED."

            if time.time() - req.created_at > TOKEN_EXPIRY_SECONDS:
                req.status = "EXPIRED"
                return False, "Denial: Approval token has expired."

            if req.tool_name != tool_name:
                return False, f"Denial: Token was issued for '{req.tool_name}', not '{tool_name}'."

            # Atomically consume
            self._consumed_tokens.add(approval_token)
            req.status = "CONSUMED"
            try:
                import taint_tracker
                taint_tracker.verify_and_consume_step_up_token(approval_token, tool_name, req.arguments)
            except Exception:
                pass
            logger.info("Token %s consumed successfully for action %s", approval_token, tool_name)
            return True, "Token verified and consumed."


_GLOBAL_GATE: Optional[ConfirmationGate] = None
_GATE_LOCK = threading.RLock()


def get_confirmation_gate() -> ConfirmationGate:
    global _GLOBAL_GATE
    with _GATE_LOCK:
        if _GLOBAL_GATE is None:
            _GLOBAL_GATE = ConfirmationGate()
        return _GLOBAL_GATE
