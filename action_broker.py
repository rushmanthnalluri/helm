"""action_broker.py - Single Unified Policy and Execution Broker for Homie.

Coordinates and strictly mediates ALL workstation actions across:
- Desktop Hotkey / Typed Ask (caller_id: "desktop_user")
- Desktop Voice Assistant (caller_id: "desktop_voice")
- Telegram Remote Control Bridge (caller_id: "telegram_remote")
- Phone Gateway PSTN calls & Web-call (caller_id: "phone_gateway")
- AI Engine Tool Loop (caller_id: "ai_engine")
- MCP Tools (caller_id: "mcp_client")

Enforces the Unified Security Policy:
1. Emergency Kill Switch check
2. Policy Supervisor state & heartbeat lease check
3. Multi-channel Canary leak inspection
4. Policy Envelope bounds (domain scoping, high-risk semantic detection)
5. Taint Tracking and out-of-band Step-Up token single-use consumption
6. Shadow mode simulation
7. Cryptographic INTENT V2 two-phase authorization
8. Privileged Complete Mediation Actuator dispatch
9. Hash-chained HMAC-SHA256 audit ledger recording
10. Automatic untrusted provenance tagging
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor
import homie_mcp
import agent_audit_ledger
import kill_switch
import taint_tracker
import shadow_mode
import canary_monitor
import policy_envelope
from policy_envelope import PolicyEnvelope, PROHIBITED_ENVELOPE_IMAGES

logger = logging.getLogger("homie.action_broker")


class ActionBroker:
    """The central unified execution broker mediating all Homie capabilities."""

    def __init__(
        self,
        supervisor_instance: Optional[homie_supervisor.PolicySupervisor] = None,
        pipe_client: Optional[Any] = None,
        pipe_name: str = r"\\.\pipe\homie_supervisor"
    ):
        self.pipe_name = pipe_name
        self.pipe_client = pipe_client
        self.envelope: Optional[PolicyEnvelope] = None

        if pipe_client:
            self.supervisor = None
            self.client = pipe_client
        elif supervisor_instance is not None:
            # Explicit test harness supervisor injection
            self.supervisor = supervisor_instance
            if self.supervisor.state != homie_supervisor.STATE_LOCKED:
                self.supervisor.state = homie_supervisor.STATE_ARMED
            self.client = homie_supervisor.SupervisorClient(self.supervisor)
            self.client.connect()
        else:
            # Check if running in strict pipe mode / target architecture
            require_pipe = os.environ.get("HOMIE_REQUIRE_PIPE") == "1"
            is_test_env = os.environ.get("HOMIE_TEST_ENV") == "1"

            if require_pipe or not is_test_env:
                # Production / target architecture: STRICT PIPE CLIENT.
                # Process holds NO in-process supervisor, NO intent key, NO actuators!
                self.supervisor = None
                self.pipe_client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=self.pipe_name)
                self.client = self.pipe_client
                try:
                    self.client.connect(timeout_sec=0.2)
                except Exception:
                    pass
            else:
                # In-memory test suite backward compatibility
                self.supervisor = homie_supervisor.PolicySupervisor()
                if self.supervisor.state != homie_supervisor.STATE_LOCKED:
                    self.supervisor.state = homie_supervisor.STATE_ARMED
                self.client = homie_supervisor.SupervisorClient(self.supervisor)
                self.client.connect()

    LEGACY_TOOL_MAP = {
        "media_control": "homie_control_media",
        "control_media": "homie_control_media",
        "place_window": "homie_place_window",
        "play_youtube": "homie_play_youtube",
        "open_app_or_url": "homie_launch_app",
        "launch_app": "homie_launch_app",
        "lock_pc": "homie_lock_workstation",
        "get_clipboard": "homie_get_clipboard",
        "set_clipboard": "homie_set_clipboard",
        "list_downloads": "homie_list_downloads",
        "get_system_vitals": "homie_get_vitals",
        "get_vitals": "homie_get_vitals",
        "send_chat_message": "homie_send_chat",
        "send_chat": "homie_send_chat",
        "close_app": "homie_close_app",
        "kill_process": "homie_kill_process",
        "kill_process_by_pid": "homie_kill_process",
        "capture_screen": "homie_capture_screen",
        "capture_screens": "homie_capture_screen",
        "safe_command": "homie_safe_command",
        "execute_safe_command": "homie_safe_command",
        "get_top_processes": "homie_get_top_processes",
    }

    def normalize_tool_name(self, name: str) -> str:
        """Normalizes shorthand tool names (e.g. 'play_youtube') to canonical 'homie_play_youtube'."""
        clean = name.strip()
        if clean in self.LEGACY_TOOL_MAP:
            return self.LEGACY_TOOL_MAP[clean]
        if not clean.startswith("homie_"):
            candidate = f"homie_{clean}"
            allowed = homie_supervisor.get_allowed_tools_map()
            if candidate in allowed:
                return candidate
        return clean

    def execute_action(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        caller_id: str = "desktop_user",
        client_token: Optional[str] = None,
        step_up_token: Optional[str] = None
    ) -> Tuple[bool, str, Any]:
        """Mediates and executes an action through the unified policy gates.
        Returns: (success: bool, message: str, result_data: Any)
        """
        args = arguments or {}
        canonical_tool = self.normalize_tool_name(tool_name)
        req_id = f"req_{int(time.time()*1000)}"

        # 0. Out-of-Process Pipe Client Branch (Fail-Closed)
        if self.supervisor is None and isinstance(getattr(self, "client", None), homie_supervisor.NamedPipeSupervisorClient):
            if not self.client.handle:
                try:
                    if not self.client.connect(timeout_sec=0.1):
                        return False, "Security Gate: Supervisor process is unreachable or disconnected (fail-closed).", None
                except Exception as conn_err:
                    return False, f"Security Gate: Supervisor connection error (fail-closed): {conn_err}", None

            try:
                reply = self.client.propose(
                    canonical_tool, args, caller_id=caller_id, client_token=client_token, step_up_token=step_up_token
                )
                if not reply or not isinstance(reply, dict):
                    return False, "Security Gate: Malformed supervisor response (fail-closed).", None

                status = reply.get("status")
                if status == "ALLOW":
                    res_val = reply.get("result")
                    return True, reply.get("reason", "Success: Action executed"), res_val
                elif status == "SHADOW":
                    return True, reply.get("reason", "Shadow mode simulated"), reply.get("result")
                else:
                    reason = reply.get("reason") or reply.get("error", "Security Gate: Action rejected by supervisor.")
                    return False, reason, reply.get("result")
            except Exception as pe:
                logger.error("Pipe communication error with supervisor: %s", pe)
                return False, f"Security Gate: Supervisor communication failure (fail-closed): {pe}", None

        # 1. State Gate: Supervisor LOCKED fails closed
        if self.supervisor.state == homie_supervisor.STATE_LOCKED:
            msg = f"Security Gate: Supervisor is LOCKED: {self.supervisor.lock_reason}"
            logger.warning("Action %s denied: %s", canonical_tool, msg)
            return False, msg, None

        # 2. Kill Switch Gate
        if kill_switch.is_kill_switch_active():
            allowed_tools = homie_supervisor.get_allowed_tools_map()
            tier = allowed_tools.get(canonical_tool, "WRITE_EXEC")
            if tier != "READ_ONLY":
                msg = "Security Gate: Emergency kill switch is actively engaged. Action blocked."
                try:
                    agent_audit_ledger.record_agent_action(caller_id, canonical_tool, tier, args, decision="DENY_KILL_SWITCH")
                except Exception:
                    pass
                return False, msg, None

        # 3. Tool Allowlist & Tier Mapping
        allowed_tools = homie_supervisor.get_allowed_tools_map()
        if canonical_tool not in allowed_tools:
            # Fallback check without homie_ prefix
            if tool_name in allowed_tools:
                canonical_tool = tool_name
            else:
                msg = f"Security Gate: Tool '{tool_name}' is not in the workstation allowlist."
                try:
                    agent_audit_ledger.record_agent_action(caller_id, canonical_tool, "UNKNOWN", args, decision="DENY_UNKNOWN_TOOL")
                except Exception:
                    pass
                return False, msg, None

        tier = allowed_tools.get(canonical_tool, "WRITE_EXEC")

        # 3.1. Phone Channel Tier Cap: Spoken phone instructions capped to READ_ONLY and REVERSIBLE
        if caller_id.startswith("phone_") and tier == "WRITE_EXEC" and not step_up_token:
            msg = f"Security Gate: Phone channel is capped to READ_ONLY and REVERSIBLE tiers. Action '{canonical_tool}' ({tier}) requires step-up authorization."
            try:
                agent_audit_ledger.record_agent_action(caller_id, canonical_tool, tier, args, decision="DENY_PHONE_TIER_CAP")
            except Exception:
                pass
            return False, msg, None

        # 4. Multi-channel Canary leak scan on arguments
        has_canary, canary_msg = canary_monitor.inspect_egress_payload(args)
        if has_canary:
            self.supervisor._transition_to_locked(f"Canary exfiltration attempt: {canary_msg}")
            return False, f"Security Alert: Canary pattern detected in parameters: {canary_msg}", None

        # 5. Rate limiting check
        rate_ok, rate_msg = shadow_mode.check_rate_limit(caller_id, tier=tier)
        if not rate_ok:
            return False, f"Security Gate: {rate_msg}", None

        # 6. Policy Envelope & Prohibited Environments Check
        if canonical_tool in ("homie_launch_app", "open_app_or_url"):
            target = (args.get("app_name") or args.get("target") or "").lower().strip()
            base = os.path.basename(target)
            if base in PROHIBITED_ENVELOPE_IMAGES or f"{base}.exe" in PROHIBITED_ENVELOPE_IMAGES:
                msg = f"Security Gate: Launching prohibited command environment '{target}' is barred."
                return False, msg, None

        if self.envelope and self.envelope.is_active:
            current_proc = args.get("target_process") or args.get("app_name")
            current_domain = args.get("domain") or args.get("url")
            current_epoch = taint_tracker.get_taint_epoch()
            env_ok, env_msg = self.envelope.check_and_consume(
                canonical_tool, args, current_proc, current_epoch, current_domain
            )
            if not env_ok:
                return False, f"Security Gate: {env_msg}", None

        # 7. Taint Tracking & Out-of-band Step-up Verification
        if step_up_token:
            valid_step_up, step_up_msg = taint_tracker.verify_and_consume_step_up_token(
                step_up_token, canonical_tool, args
            )
            if not valid_step_up:
                return False, f"Security Gate: Step-up token rejected: {step_up_msg}", None
            logger.info("Broker authorized action '%s' via consumed step-up token for caller '%s'", canonical_tool, caller_id)
        else:
            allowed, requires_step_up, taint_reason = taint_tracker.check_action_privilege(
                caller_id, tier, canonical_tool, args
            )
            if not allowed:
                return False, f"Security Gate: {taint_reason}", None

        # 8. Shadow Mode Simulation
        if shadow_mode.is_shadow_mode_active() and tier in ("WRITE_EXEC", "ELEVATED_CONFIRM"):
            record = shadow_mode.record_simulated_action(caller_id, canonical_tool, tier, args)
            sim_msg = f"[SHADOW_SIMULATION] {canonical_tool} simulated with parameters {args}"
            return True, sim_msg, record

        # 9. TWO-PHASE COMPLETE MEDIATION EXECUTION:
        # Phase 1: Supervisor mints unforgeable cryptographic INTENT V2 token with args_hash
        seq = self.supervisor.last_client_seq + 1
        self.supervisor.last_client_seq = seq
        intent_token = self.supervisor.mint_intent_token(canonical_tool, args, caller_id, seq)

        # Phase 2: Privileged SupervisorActuator verifies INTENT V2 token & single-use consumption
        try:
            output = self.supervisor.actuator.execute_actuator(
                canonical_tool, args, caller_id=caller_id, client_token=client_token, intent_token=intent_token, seq=seq
            )
            success = not str(output).startswith(("Error:", "Security Gate:", "Blocked:"))
            return success, str(output), output
        except homie_supervisor.CompleteMediationBreachError as cme:
            self.supervisor._transition_to_locked(f"Complete mediation violation: {cme}")
            return False, f"Security Gate: {cme}", None
        except Exception as e:
            return False, f"Execution failed: {e}", None


_GLOBAL_BROKER: Optional[ActionBroker] = None

def get_action_broker() -> ActionBroker:
    global _GLOBAL_BROKER
    if _GLOBAL_BROKER is None:
        _GLOBAL_BROKER = ActionBroker()
    return _GLOBAL_BROKER

def execute_action(
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    caller_id: str = "desktop_user",
    client_token: Optional[str] = None,
    step_up_token: Optional[str] = None
) -> Tuple[bool, str, Any]:
    """Public helper to route any workstation action through the single unified policy broker."""
    return get_action_broker().execute_action(
        tool_name, arguments, caller_id=caller_id, client_token=client_token, step_up_token=step_up_token
    )
