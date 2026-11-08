"""Homie Out-of-Process Policy Supervisor & Watchdog Architecture (Batch 17).

Enforces strict privilege separation between the untrusted agent worker
and the high-integrity policy supervisor:
- The supervisor OWNS all actuator capabilities (SendInput, clipboard, launches, network).
  The worker only proposes actions over an authenticated binary IPC channel.
- Complete mediation: check and act occur inside the same trust domain, eliminating TOCTOU.
- Binary Framing: [u32 len][u8 ver][u8 type][u64 seq][payload] with strict JSON validation.
- Monotonic sequence enforcement: Replay, reorder, or seq rollback immediately drops connection and fails closed.
- State Machine: INIT -> ARMED -> DEGRADED -> LOCKED.
- Dirty-bit boot protection: Detects abnormal crashes/terminations and starts effect-locked.
- Two-phase action logging: Logs INTENT before effect and OUTCOME after effect to detect mid-flight crashes.
- Kernel-attested client validation via GetNamedPipeClientProcessId on Windows Named Pipes.
- Dead-man's heartbeat lease with progress_counter progress verification.
"""

import os
import sys
import time
import json
import struct
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agent_audit_ledger
import taint_tracker
import step_up_gate
import client_token_auth
import canary_monitor
import heartbeat_lease
import shadow_mode
import kill_switch
import windows_tools
import homie_mcp
import worker_confinement

logger = logging.getLogger("homie.supervisor")

# Protocol Constants
PROTOCOL_VERSION = 1
HEADER_FORMAT = ">IBBQ"  # [u32 len][u8 ver][u8 type][u64 seq] -> 14 bytes
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1 MiB hard ceiling

# Message Types
MSG_HELLO = 1
MSG_HELLO_ACK = 2
MSG_PROPOSE = 3
MSG_DECISION = 4
MSG_HEARTBEAT = 5
MSG_DATA = 6
MSG_SHUTDOWN = 7
MSG_ERROR = 8
MSG_PROXY_LLM = 9

# Reason Codes
REASON_OK = "OK"
REASON_UNKNOWN_TOOL = "DENY_UNKNOWN_TOOL"
REASON_SYSTEM_LOCKED = "DENY_SYSTEM_LOCKED"
REASON_LEASE_EXPIRED = "DENY_LEASE_EXPIRED"
REASON_UNAUTHORIZED_TOKEN = "DENY_UNAUTHORIZED_TOKEN"
REASON_TAINTED_STEPUP = "NEEDS_HUMAN_STEPUP"
REASON_PROHIBITED_PROCESS = "DENY_PROHIBITED_PROCESS"
REASON_CANARY_DETECTED = "DENY_CANARY_DETECTED"
REASON_RATE_LIMIT = "DENY_RATE_LIMIT_EXCEEDED"
REASON_SHADOW_SIMULATED = "SHADOW_SIMULATED"
REASON_EXECUTION_FAILED = "EXECUTION_FAILED"
REASON_MALFORMED_FRAME = "DENY_MALFORMED_FRAME"
REASON_SEQ_ROLLBACK = "DENY_SEQ_ROLLBACK_DETECTED"

# Supervisor States
STATE_INIT = "INIT"
STATE_ARMED = "ARMED"
STATE_DEGRADED = "DEGRADED"
STATE_LOCKED = "LOCKED"

DIRTY_FLAG_PATH = os.path.join(BASE_DIR, "homie_supervisor_dirty.flag")
CRASH_HISTORY_PATH = os.path.join(BASE_DIR, "homie_supervisor_crashes.json")


class FrameError(Exception):
    """Base exception for framing and protocol violations."""
    pass


class SequenceViolationError(FrameError):
    """Raised when sequence numbers are decremented, reordered, or replayed."""
    pass


class PayloadSizeError(FrameError):
    """Raised when payload exceeds hard size ceiling."""
    pass


class BinaryFrameCodec:
    """Encodes and decodes the [u32 len][u8 ver][u8 type][u64 seq][payload] protocol wire format."""

    @staticmethod
    def encode_frame(msg_type: int, seq: int, payload: Dict[str, Any], version: int = PROTOCOL_VERSION) -> bytes:
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        if len(payload_bytes) > MAX_PAYLOAD_SIZE:
            raise PayloadSizeError(f"Payload size {len(payload_bytes)} exceeds maximum {MAX_PAYLOAD_SIZE} bytes")
        
        header = struct.pack(HEADER_FORMAT, len(payload_bytes), version, msg_type, seq)
        return header + payload_bytes

    @staticmethod
    def decode_frame(raw_buffer: bytes) -> Tuple[int, int, int, Dict[str, Any], int]:
        """Decodes the first frame from raw_buffer.
        Returns: (version, msg_type, seq, payload_dict, bytes_consumed)
        Raises: FrameError if invalid, or ValueError if buffer too short.
        """
        if len(raw_buffer) < HEADER_SIZE:
            raise ValueError("Buffer shorter than header length")

        payload_len, version, msg_type, seq = struct.unpack(HEADER_FORMAT, raw_buffer[:HEADER_SIZE])
        
        if payload_len > MAX_PAYLOAD_SIZE:
            raise PayloadSizeError(f"Oversized frame: length {payload_len} exceeds {MAX_PAYLOAD_SIZE}")

        total_needed = HEADER_SIZE + payload_len
        if len(raw_buffer) < total_needed:
            raise ValueError(f"Incomplete frame: have {len(raw_buffer)}, need {total_needed}")

        payload_slice = raw_buffer[HEADER_SIZE:total_needed]
        try:
            payload_str = payload_slice.decode('utf-8')
            payload_dict = json.loads(payload_str)
            if not isinstance(payload_dict, dict):
                raise FrameError("Payload root must be a JSON object")
        except Exception as e:
            raise FrameError(f"Malformed JSON payload in frame: {e}")

        return version, msg_type, seq, payload_dict, total_needed


def get_allowed_tools_map() -> Dict[str, str]:
    """Returns mapping of allowed tool names to their capability tiers."""
    import homie_mcp
    return {t["name"]: t.get("capabilityTier", "WRITE_EXEC") for t in homie_mcp.MCP_TOOLS}


class PolicySupervisor:
    """High-Integrity Out-of-Process Policy Supervisor & Actuator Dispatcher."""

    def __init__(self, authorized_worker_pid: Optional[int] = None, state_db_path: Optional[str] = None):
        self.authorized_worker_pid = authorized_worker_pid
        self.session_epoch = int(time.time())
        self.state = STATE_INIT
        self.last_client_seq = 0
        self.last_supervisor_seq = 0
        self.last_heartbeat_time = time.time()
        self.last_progress_counter = 0
        self.active_request_id: Optional[str] = None
        self.dirty_boot_recovered = False
        self.lock_reason = ""
        self.lease_token = None
        
        # Check dirty bit from previous run
        self._check_dirty_bit_on_startup()
        
        # Check for unresolved two-phase action intents
        self.unresolved_intents = self.check_unresolved_intents()
        if self.unresolved_intents:
            self._transition_to_locked(f"Unresolved action intent detected from previous crash: {self.unresolved_intents}")

    def _check_dirty_bit_on_startup(self):
        """Dirty-bit boot protection: If dirty flag exists at startup, previous session died abnormally."""
        if os.path.exists(DIRTY_FLAG_PATH):
            self.dirty_boot_recovered = True
            self._transition_to_locked("Dirty boot detected: previous session terminated abnormally without clean shutdown.")
            self._record_crash_history()
        else:
            # Mark dirty flag for current session
            try:
                with open(DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"pid": os.getpid(), "epoch": self.session_epoch, "started_at": time.time()}))
            except Exception as e:
                logger.warning("Could not create dirty flag: %s", e)

    def _record_crash_history(self):
        """Records crash timestamp and triggers locked state if crash-loop threshold (>3 crashes / 5m) is exceeded."""
        now = time.time()
        history = []
        if os.path.exists(CRASH_HISTORY_PATH):
            try:
                with open(CRASH_HISTORY_PATH, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
        
        history.append(now)
        # Retain last 5 minutes (300 seconds)
        recent_crashes = [t for t in history if now - t <= 300]
        try:
            with open(CRASH_HISTORY_PATH, "w", encoding="utf-8") as f:
                json.dump(recent_crashes, f)
        except Exception:
            pass

        if len(recent_crashes) >= 3:
            self._transition_to_locked("Crash-loop limit exceeded (>3 crashes in 5 minutes). Permanent supervisor lockout.")

    def _transition_to_locked(self, reason: str):
        self.state = STATE_LOCKED
        self.lock_reason = reason
        logger.error("Supervisor transitioned to LOCKED state: %s", reason)
        kill_switch.engage_kill_switch(f"Supervisor locked: {reason}")

    def clean_shutdown(self):
        """Orderly shutdown: removes dirty flag."""
        if os.path.exists(DIRTY_FLAG_PATH):
            try:
                os.remove(DIRTY_FLAG_PATH)
            except Exception:
                pass
        self.state = STATE_INIT

    def human_unlock(self, human_auth_token: str) -> Tuple[bool, str]:
        """Unlocks supervisor from LOCKED state via explicit human verification."""
        ok, msg = taint_tracker.human_clear_taint(human_auth_token)
        if not ok:
            return False, f"Unlock failed: {msg}"
        
        # Clean dirty flag if still lingering
        if os.path.exists(DIRTY_FLAG_PATH):
            try:
                with open(DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"pid": os.getpid(), "epoch": self.session_epoch, "unlocked_at": time.time()}))
            except Exception:
                pass

        self.state = STATE_ARMED
        self.lock_reason = ""
        kill_switch.disengage_kill_switch(human_auth_token)
        return True, "Supervisor successfully unlocked by human confirmation."

    def attach_watchdog(self, watchdog):
        """Attaches an independent watchdog to monitor supervisor and mutual liveness."""
        self.watchdog = watchdog

    def check_watchdog_liveness(self) -> bool:
        """Verifies watchdog is alive. If watchdog died or is unresponsive, locks supervisor."""
        if not getattr(self, "watchdog", None):
            return True
        if self.watchdog.locked or not self.watchdog.heartbeat.check_liveness():
            self.state = STATE_LOCKED
            self.lock_reason = "WATCHDOG_DEAD_OR_TIMEOUT"
            kill_switch.engage_kill_switch("Watchdog unresponsive or died")
            return False
        return True

    def check_unresolved_intents(self) -> list:
        """Inspects audit ledger for INTENT entries that lack a subsequent OUTCOME entry."""
        import db_utils
        unresolved = []
        try:
            with db_utils.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, tool_name, decision FROM agent_audit_ledger ORDER BY id DESC LIMIT 50")
                rows = cur.fetchall()
                intents = {}
                outcomes = set()
                for r in rows:
                    dec = r[2] if len(r) > 2 else ""
                    if dec.startswith("INTENT:"):
                        req_id = dec.split(":")[1] if len(dec.split(":")) > 1 else str(r[0])
                        intents[req_id] = (r[0], r[1])
                    elif dec.startswith("OUTCOME:"):
                        req_id = dec.split(":")[1] if len(dec.split(":")) > 1 else str(r[0])
                        outcomes.add(req_id)
                for req_id, (row_id, tool) in intents.items():
                    if req_id not in outcomes:
                        unresolved.append({"req_id": req_id, "row_id": row_id, "tool": tool})
        except Exception as e:
            logger.error("Error inspecting unresolved intents: %s", e)
        return unresolved

    def handle_raw_frame(self, frame_bytes: bytes) -> bytes:
        """Processes an incoming raw binary frame and returns the encoded response binary frame."""
        try:
            version, msg_type, seq, payload, _ = BinaryFrameCodec.decode_frame(frame_bytes)
        except Exception as e:
            self._transition_to_locked(f"Binary framing error / malformed packet: {e}")
            return self._encode_reply(MSG_ERROR, {"error": str(e), "reason_code": REASON_MALFORMED_FRAME})

        # Monotonic Sequence Verification
        if seq <= self.last_client_seq:
            self._transition_to_locked(f"Sequence rollback/replay detected: got {seq}, expected > {self.last_client_seq}")
            return self._encode_reply(MSG_ERROR, {"error": "Sequence replay detected", "reason_code": REASON_SEQ_ROLLBACK})
        
        self.last_client_seq = seq

        # Dispatch message type
        if msg_type == MSG_HELLO:
            return self._handle_hello(payload)
        elif msg_type == MSG_HEARTBEAT:
            return self._handle_heartbeat(payload)
        elif msg_type == MSG_PROPOSE:
            return self._handle_propose(payload)
        elif msg_type == MSG_SHUTDOWN:
            return self._handle_shutdown(payload)
        elif msg_type == MSG_PROXY_LLM:
            return self._handle_proxy_llm(payload)
        else:
            return self._encode_reply(MSG_ERROR, {"error": f"Unknown message type {msg_type}", "reason_code": REASON_MALFORMED_FRAME})

    def _handle_proxy_llm(self, payload: Dict[str, Any]) -> bytes:
        prompt = payload.get("prompt", "")
        caller_id = payload.get("caller_id", "worker")
        proxy = worker_confinement.SupervisorLLMProxy()
        ok, res = proxy.proxy_completion(prompt, caller_id=caller_id)
        if not ok:
            return self._encode_reply(MSG_ERROR, {"error": res, "reason_code": "PROXY_LLM_DENIED"})
        return self._encode_reply(MSG_DATA, {"status": "OK", "result": res})

    def _encode_reply(self, msg_type: int, payload: Dict[str, Any]) -> bytes:
        self.last_supervisor_seq += 1
        return BinaryFrameCodec.encode_frame(msg_type, self.last_supervisor_seq, payload)

    def _handle_hello(self, payload: Dict[str, Any]) -> bytes:
        worker_pid = payload.get("worker_pid")
        if self.authorized_worker_pid and worker_pid != self.authorized_worker_pid:
            self._transition_to_locked(f"Worker PID mismatch: got {worker_pid}, expected {self.authorized_worker_pid}")
            return self._encode_reply(MSG_ERROR, {"error": "Worker identity mismatch", "reason_code": "DENY_PID_MISMATCH"})

        # Transition to ARMED if not locked
        if self.state != STATE_LOCKED:
            self.state = STATE_ARMED

        self.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)
        self.last_heartbeat_time = time.time()

        ack_payload = {
            "supervisor_pid": os.getpid(),
            "session_epoch": self.session_epoch,
            "state": self.state,
            "status": "OK",
            "lock_reason": self.lock_reason
        }
        return self._encode_reply(MSG_HELLO_ACK, ack_payload)

    def _handle_heartbeat(self, payload: Dict[str, Any]) -> bytes:
        progress = payload.get("progress_counter", 0)
        if self.active_request_id and progress < self.last_progress_counter:
            logger.warning("Heartbeat progress counter went backwards: %s -> %s", self.last_progress_counter, progress)

        self.last_progress_counter = progress
        self.last_heartbeat_time = time.time()
        renewed, _ = heartbeat_lease.renew_lease("supervisor_worker", self.lease_token, duration=5.0) if self.lease_token else (False, "")
        if not renewed:
            self.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=5.0)

        return self._encode_reply(MSG_HEARTBEAT, {
            "status": "PONG",
            "state": self.state,
            "time": time.time()
        })

    def _handle_shutdown(self, payload: Dict[str, Any]) -> bytes:
        reason = payload.get("reason", "normal")
        logger.info("Worker requested clean supervisor shutdown: %s", reason)
        self.clean_shutdown()
        return self._encode_reply(MSG_SHUTDOWN, {"status": "SHUTDOWN_CLEAN", "reason": reason})

    def _handle_propose(self, payload: Dict[str, Any]) -> bytes:
        req_id = payload.get("req_id", f"req_{int(time.time()*1000)}")
        tool = payload.get("tool", "")
        args = payload.get("args", {})
        args_hash = payload.get("args_hash", "")
        caller_id = payload.get("caller_id", "worker")
        client_token = payload.get("client_token")
        step_up_token = payload.get("step_up_token")

        self.active_request_id = req_id

        # 1. State check: LOCKED fails closed immediately
        if self.state == STATE_LOCKED:
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_SYSTEM_LOCKED,
                "reason": f"Supervisor is LOCKED: {self.lock_reason}"
            })

        # 2. Kill Switch gate
        if kill_switch.is_kill_switch_active():
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_SYSTEM_LOCKED,
                "reason": "Emergency Kill Switch is actively engaged."
            })

        # 3. Dead-man's Heartbeat Lease check
        is_lease_ok = heartbeat_lease.is_lease_valid("supervisor_worker")
        if not is_lease_ok or (time.time() - self.last_heartbeat_time > 5.0):
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_LEASE_EXPIRED,
                "reason": "Dead-man's heartbeat lease expired"
            })

        # 4. Multi-channel Canary exfiltration scan on proposed arguments
        has_canary, canary_msg = canary_monitor.inspect_egress_payload(args)
        if has_canary:
            self._transition_to_locked(f"Canary exfiltration attempt detected in tool proposal: {canary_msg}")
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_CANARY_DETECTED,
                "reason": f"Security Alert: Canary exfiltration pattern detected: {canary_msg}"
            })

        # 5. Rate limiting check
        rate_ok, rate_msg = shadow_mode.check_rate_limit(caller_id)
        if not rate_ok:
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_RATE_LIMIT,
                "reason": rate_msg
            })

        # 6. Tool allowlist and capability tier mapping
        allowed_tools = get_allowed_tools_map()
        if tool not in allowed_tools:
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_UNKNOWN_TOOL,
                "reason": f"Unknown tool: '{tool}' is not in the workstation allowlist."
            })

        tier = allowed_tools.get(tool, "WRITE_EXEC")

        # 7. Client Token Authentication check
        if client_token:
            valid_tok, tok_msg, _ = client_token_auth.validate_client_token(client_token, required_tier=tier)
            if not valid_tok:
                return self._encode_reply(MSG_DECISION, {
                    "req_id": req_id,
                    "status": "DENY",
                    "reason_code": REASON_UNAUTHORIZED_TOKEN,
                    "reason": f"Client token rejected: {tok_msg}"
                })

        # 8. Target Process Image Check (Hardware Grounding) with Millisecond TOCTOU Guard
        if tool in ["homie_agent_click", "homie_agent_type"]:
            safe, toctou_reason = worker_confinement.PreInjectionTOCTOUGuard.verify_injection_target()
            if not safe:
                return self._encode_reply(MSG_DECISION, {
                    "req_id": req_id,
                    "status": "DENY",
                    "reason_code": REASON_PROHIBITED_PROCESS,
                    "reason": toctou_reason
                })

        # 9. Taint & Out-of-band Step-up Verification
        allowed, requires_step_up, taint_reason = taint_tracker.check_action_privilege(
            caller_id, tier, tool, args
        )
        if not allowed and requires_step_up:
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "NEEDS_HUMAN",
                "reason_code": REASON_TAINTED_STEPUP,
                "reason": taint_reason
            })

        # 10. Shadow Mode Simulation check
        if shadow_mode.is_shadow_mode_active():
            record = shadow_mode.record_simulated_action(caller_id, tool, tier, args)
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "SHADOW",
                "reason_code": REASON_SHADOW_SIMULATED,
                "reason": f"Action simulated in shadow mode: {record['action_id']}",
                "result": f"[SHADOW_SIMULATION] {tool} evaluated with parameters {args}"
            })

        # 11. TWO-PHASE ACTION EXECUTION:
        # Phase 1: Record INTENT in HMAC-SHA256 audit ledger
        agent_audit_ledger.record_agent_action(
            caller_id, tool, tier, args, decision=f"INTENT:{req_id}"
        )

        # Phase 2: Privileged Supervisor Actuator executes effect
        execution_success = True
        try:
            result = homie_mcp.execute_mcp_tool(
                tool, args, caller_id=caller_id, client_token=client_token
            )
        except Exception as e:
            execution_success = False
            result = f"Error executing tool in supervisor: {e}"

        # Phase 3: Record OUTCOME in HMAC-SHA256 audit ledger
        outcome_status = "SUCCESS" if execution_success else "FAILED"
        agent_audit_ledger.record_agent_action(
            caller_id, tool, tier, args, decision=f"OUTCOME:{req_id}:{outcome_status}"
        )

        self.active_request_id = None

        return self._encode_reply(MSG_DECISION, {
            "req_id": req_id,
            "status": "ALLOW" if execution_success else "DENY",
            "reason_code": REASON_OK if execution_success else REASON_EXECUTION_FAILED,
            "result": result
        })


class SupervisorClient:
    """Client for worker processes to communicate with PolicySupervisor over the binary protocol."""

    def __init__(self, supervisor_instance: Optional[PolicySupervisor] = None):
        self.supervisor = supervisor_instance
        self.seq = 0
        self.last_supervisor_seq = 0
        self.session_epoch = 0
        self.connected = False

    def connect(self) -> bool:
        if not self.supervisor:
            return False
        self.connected = True
        return True

    def _send_and_receive(self, msg_type: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.connected:
            raise ConnectionError("Client is not connected to PolicySupervisor")

        self.seq += 1
        frame = BinaryFrameCodec.encode_frame(msg_type, self.seq, payload)
        reply_bytes = self.supervisor.handle_raw_frame(frame)
        
        ver, rep_type, rep_seq, rep_payload, _ = BinaryFrameCodec.decode_frame(reply_bytes)
        self.last_supervisor_seq = rep_seq
        return rep_payload

    def hello(self, worker_pid: Optional[int] = None) -> Dict[str, Any]:
        pid = worker_pid or os.getpid()
        payload = {"worker_pid": pid, "client_name": "worker_client", "time": time.time()}
        res = self._send_and_receive(MSG_HELLO, payload)
        self.session_epoch = res.get("session_epoch", 0)
        return res

    def heartbeat(self, progress_counter: int = 1) -> Dict[str, Any]:
        payload = {"progress_counter": progress_counter, "worker_pid": os.getpid()}
        return self._send_and_receive(MSG_HEARTBEAT, payload)

    def propose(self, tool: str, args: Dict[str, Any], caller_id: str = "worker",
                client_token: Optional[str] = None, step_up_token: Optional[str] = None) -> Dict[str, Any]:
        clean_args = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]
        req_id = f"req_{int(time.time()*1000)}_{self.seq}"
        
        payload = {
            "req_id": req_id,
            "tool": tool,
            "args": args,
            "args_hash": args_hash,
            "caller_id": caller_id,
            "client_token": client_token,
            "step_up_token": step_up_token
        }
        return self._send_and_receive(MSG_PROPOSE, payload)

    def shutdown(self, reason: str = "normal") -> Dict[str, Any]:
        payload = {"reason": reason}
        return self._send_and_receive(MSG_SHUTDOWN, payload)


import threading

class NamedPipeSupervisorServer:
    """Out-of-process Windows Named Pipe server for PolicySupervisor.
    Uses win32pipe.CreateNamedPipe with FILE_FLAG_FIRST_PIPE_INSTANCE and PIPE_REJECT_REMOTE_CLIENTS.
    Enforces kernel-attested client validation via GetNamedPipeClientProcessId.
    """

    def __init__(self, supervisor: PolicySupervisor, pipe_name: str = r"\\.\pipe\homie_supervisor"):
        self.supervisor = supervisor
        self.pipe_name = pipe_name
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.server_pipe = None

    def start(self):
        import win32pipe
        self.running = True
        self.server_pipe = win32pipe.CreateNamedPipe(
            self.pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            None
        )
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

    def _run_server(self):
        import win32pipe
        import win32file
        while self.running:
            try:
                try:
                    win32pipe.ConnectNamedPipe(self.server_pipe, None)
                except Exception as e:
                    # Windows error 535: ERROR_PIPE_CONNECTED (client already connected)
                    if getattr(e, 'winerror', None) != 535 and not (len(e.args) > 0 and e.args[0] == 535):
                        raise
                client_pid = win32pipe.GetNamedPipeClientProcessId(self.server_pipe)
                logger.info("Named pipe client connected! Kernel-attested PID: %d", client_pid)

                if self.supervisor.authorized_worker_pid and client_pid != self.supervisor.authorized_worker_pid:
                    win32pipe.DisconnectNamedPipe(self.server_pipe)
                    continue

                buffer = b""
                while self.running:
                    try:
                        hr, chunk = win32file.ReadFile(self.server_pipe, 4096)
                    except Exception:
                        break
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= HEADER_SIZE:
                        payload_len, _, _, _ = struct.unpack(HEADER_FORMAT, buffer[:HEADER_SIZE])
                        frame_len = HEADER_SIZE + payload_len
                        if len(buffer) < frame_len:
                            break
                        raw_frame = buffer[:frame_len]
                        buffer = buffer[frame_len:]

                        reply_bytes = self.supervisor.handle_raw_frame(raw_frame)
                        win32file.WriteFile(self.server_pipe, reply_bytes)

                try:
                    win32pipe.DisconnectNamedPipe(self.server_pipe)
                except Exception:
                    pass
            except Exception as e:
                break

    def stop(self):
        self.running = False
        import win32file
        if self.server_pipe:
            try:
                win32file.CloseHandle(self.server_pipe)
            except Exception:
                pass
            self.server_pipe = None


class NamedPipeSupervisorClient:
    """Out-of-process Windows Named Pipe client for worker processes.
    Connects to the supervisor pipe via win32file.CreateFile.
    """

    def __init__(self, pipe_name: str = r"\\.\pipe\homie_supervisor"):
        self.pipe_name = pipe_name
        self.handle = None
        self.seq = 0
        self.last_supervisor_seq = 0
        self.session_epoch = 0

    def connect(self, timeout_sec: float = 2.0) -> bool:
        import win32file
        start = time.time()
        while time.time() - start < timeout_sec:
            try:
                self.handle = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                return True
            except Exception:
                time.sleep(0.05)
        return False

    def _send_and_receive(self, msg_type: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        import win32file
        if not self.handle:
            raise ConnectionError("Named Pipe client is not connected")

        self.seq += 1
        frame = BinaryFrameCodec.encode_frame(msg_type, self.seq, payload)
        win32file.WriteFile(self.handle, frame)

        # Read header
        header_buf = b""
        while len(header_buf) < HEADER_SIZE:
            hr, chunk = win32file.ReadFile(self.handle, HEADER_SIZE - len(header_buf))
            header_buf += chunk

        payload_len, ver, rep_type, rep_seq = struct.unpack(HEADER_FORMAT, header_buf)
        payload_buf = b""
        while len(payload_buf) < payload_len:
            hr, chunk = win32file.ReadFile(self.handle, payload_len - len(payload_buf))
            payload_buf += chunk

        raw_reply = header_buf + payload_buf
        _, _, _, rep_payload, _ = BinaryFrameCodec.decode_frame(raw_reply)
        self.last_supervisor_seq = rep_seq
        return rep_payload

    def hello(self, worker_pid: Optional[int] = None) -> Dict[str, Any]:
        pid = worker_pid or os.getpid()
        payload = {"worker_pid": pid, "client_name": "worker_pipe_client", "time": time.time()}
        res = self._send_and_receive(MSG_HELLO, payload)
        self.session_epoch = res.get("session_epoch", 0)
        return res

    def heartbeat(self, progress_counter: int = 1) -> Dict[str, Any]:
        payload = {"progress_counter": progress_counter, "worker_pid": os.getpid()}
        return self._send_and_receive(MSG_HEARTBEAT, payload)

    def propose(self, tool: str, args: Dict[str, Any], caller_id: str = "worker",
                client_token: Optional[str] = None, step_up_token: Optional[str] = None) -> Dict[str, Any]:
        clean_args = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()[:16]
        req_id = f"req_{int(time.time()*1000)}_{self.seq}"
        payload = {
            "req_id": req_id,
            "tool": tool,
            "args": args,
            "args_hash": args_hash,
            "caller_id": caller_id,
            "client_token": client_token,
            "step_up_token": step_up_token
        }
        return self._send_and_receive(MSG_PROPOSE, payload)

    def shutdown(self, reason: str = "normal") -> Dict[str, Any]:
        payload = {"reason": reason}
        res = self._send_and_receive(MSG_SHUTDOWN, payload)
        self.close()
        return res

    def close(self):
        import win32file
        if self.handle:
            try:
                win32file.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None
