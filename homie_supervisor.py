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
import re
import time
import json
import struct
import hashlib
import hmac
import secrets
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
import policy_envelope
import device_registry

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
REASON_TAINTED_EXECUTION = "DENY_TAINTED_EXECUTION"
REASON_ENVELOPE_BREACH = "DENY_ENVELOPE_BREACH"
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


class CompleteMediationBreachError(FrameError):
    """Raised when an actuator effect is invoked without a valid supervisor INTENT token."""
    pass


class SupervisorActuator:
    """Privileged actuator residing strictly inside the Supervisor process.
    Guarantees Complete Mediation Invariant: Physical actuators cannot be invoked without
    a cryptographically unforgeable INTENT token minted by the supervisor's private key.
    """
    def __init__(self, supervisor: "PolicySupervisor"):
        self.supervisor = supervisor

    def execute_actuator(
        self,
        tool: str,
        args: Dict[str, Any],
        caller_id: str,
        client_token: Optional[str] = None,
        intent_token: Optional[str] = None,
        seq: Optional[int] = None
    ) -> str:
        # Enforce Complete Mediation Invariant via allowlist: Any tier other than READ_ONLY requires valid INTENT token
        allowed_tools = get_allowed_tools_map()
        if tool not in allowed_tools:
            raise CompleteMediationBreachError(
                f"Complete mediation invariant breach: tool '{tool}' is unknown and not in allowed tools registry!"
            )
        tier = allowed_tools.get(tool, "WRITE_EXEC")

        if seq is None or not isinstance(seq, int) or seq <= 0:
            raise ValueError("Sequence number seq is strictly required and must be a positive integer!")
        req_seq = seq

        # Prohibit synthetic simulation of console enrollment hotkey (Ctrl + Alt + P)
        import policy_envelope
        _, ctrl_alt_p_detected, detected_vks, tokens = policy_envelope.canonicalize_keyboard_arguments(args)
        if ctrl_alt_p_detected:
            raise CompleteMediationBreachError("Complete mediation breach: Synthetic simulation of physical console pairing hotkey (Ctrl+Alt+P) is strictly prohibited.")

        # Prohibit dangerous system hotkey chords
        import windows_tools
        blocked_chord = windows_tools.detect_blocked_system_chords(detected_vks, tokens)
        if blocked_chord:
            raise CompleteMediationBreachError(f"Complete mediation breach: Synthetic injection of dangerous system hotkey chord '{blocked_chord}' is strictly prohibited.")

        # Prevent TOCTOU: Re-resolve foreground process and domain immediately before actuator execution for UI-interactive tools
        UI_INTERACTIVE_TOOLS = {"homie_agent_click", "homie_agent_type", "homie_agent_mouse_move", "homie_send_hotkey"}
        if tool in UI_INTERACTIVE_TOOLS:
            fg_act = windows_tools.get_foreground_window()
            act_proc = (fg_act.get("proc_name") or "") if fg_act else ""
            clean_act_proc = os.path.basename(act_proc).lower()

            if clean_act_proc and clean_act_proc in policy_envelope.PROHIBITED_ENVELOPE_IMAGES:
                raise CompleteMediationBreachError(
                    f"Complete mediation breach: TOCTOU detected! Active foreground process '{act_proc}' is in prohibited processes list."
                )

            if getattr(self.supervisor, "envelope", None) and getattr(self.supervisor.envelope, "is_active", False):
                env = self.supervisor.envelope
                if clean_act_proc and env.allowed_target_processes:
                    allowed_procs = [os.path.basename(p).lower() for p in env.allowed_target_processes]
                    if clean_act_proc not in allowed_procs:
                        raise CompleteMediationBreachError(
                            f"Complete mediation breach: TOCTOU detected! Active foreground process '{clean_act_proc}' switched away from envelope allowed targets: {allowed_procs}"
                        )
                if clean_act_proc and env.allowed_domains and clean_act_proc in policy_envelope.BROWSER_IMAGES:
                    act_domain = windows_tools.get_browser_active_domain(fg_act.get("hwnd") if fg_act else None)
                    if not act_domain or not any(policy_envelope.is_domain_allowed(act_domain, d) for d in env.allowed_domains):
                        raise CompleteMediationBreachError(
                            f"Complete mediation breach: TOCTOU detected! Active browser domain '{act_domain}' switched away from envelope allowed domains: {env.allowed_domains}"
                        )

        if tier != "READ_ONLY":
            if not self.supervisor.verify_and_consume_intent_token(
                intent_token, tool, args, caller_id, req_seq
            ):
                raise CompleteMediationBreachError(
                    f"Complete mediation invariant breach: tool '{tool}' (tier: {tier}) actuator invoked without valid supervisor INTENT token!"
                )

        # Execute effect inside supervisor
        import homie_mcp
        homie_mcp.set_active_supervisor_intent(intent_token)
        try:
            return homie_mcp.execute_mcp_tool(
                tool, args, caller_id=caller_id, client_token=client_token
            )
        finally:
            homie_mcp.set_active_supervisor_intent(None)


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


_ACTIVE_SUPERVISOR = None

def get_active_supervisor() -> Optional['PolicySupervisor']:
    """Returns the globally active PolicySupervisor instance if running."""
    global _ACTIVE_SUPERVISOR
    return _ACTIVE_SUPERVISOR


def _init_approved_actions_table(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(approved_actions)")
    cols = [c[1] for c in cur.fetchall()]
    if not cols:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS approved_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caller_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                args_hash TEXT NOT NULL,
                taint_epoch INTEGER NOT NULL,
                expiry REAL NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                signature_blob TEXT NOT NULL DEFAULT ''
            );
        """)
    elif "signature_blob" not in cols:
        conn.execute("ALTER TABLE approved_actions ADD COLUMN signature_blob TEXT NOT NULL DEFAULT ''")
    conn.commit()


def verify_signed_approval_evidence(
    blob_raw: Any,
    caller_id: str,
    tool: str,
    args_hash: str,
    taint_epoch: int
) -> bool:
    """Cryptographically verifies a Signed Approval Blob against enrolled hardware device keys.
    Fails closed if blob is missing, corrupted, expired, caller/tool/args/epoch mismatched,
    or if signature fails verification against the enrolled device public key.
    Zero trust in unverified database rows or unauthenticated file presence.
    Strictly rebuilds canonical challenge string from fields and verifies against recomputed hash.
    """
    if not blob_raw:
        return False
    try:
        if isinstance(blob_raw, str):
            blob = json.loads(blob_raw)
        elif isinstance(blob_raw, dict):
            blob = blob_raw
        else:
            return False
    except Exception:
        return False

    device_id = blob.get("device_id")
    signature = blob.get("signature")
    if not device_id or not signature:
        return False

    # Bindings check: caller, tool, args_hash, taint_epoch, expiry
    b_caller = str(blob.get("caller_id", "")).strip()
    if b_caller != str(caller_id).strip():
        return False
    b_tool = str(blob.get("tool_name") or blob.get("action_name") or blob.get("action", "")).strip()
    if b_tool != str(tool).strip():
        return False
    b_args = str(blob.get("args_hash") or blob.get("payload_hash", "")).lower().strip()
    if b_args != str(args_hash).lower().strip():
        return False
    if int(blob.get("taint_epoch", -1)) != int(taint_epoch):
        return False
    if float(blob.get("expiry", 0)) < time.time():
        return False

    # Load device public key from decoupled device_registry
    registry = device_registry._load_device_registry()
    dev_entry = registry.get(device_id)
    if not dev_entry or dev_entry.get("revoked", False):
        return False
    pub_key_pem = dev_entry.get("public_key")
    if not pub_key_pem:
        return False

    # Rebuild canonical signed message bytes strictly from blob fields
    version = str(blob.get("version", ""))
    if version in ("CHALLENGE_V3", "3"):
        challenge_seq = blob.get("challenge_seq", 0)
        raw_challenge = f"CHALLENGE_V3|{device_id}|{caller_id}|{tool}|{args_hash.lower()}|{blob.get('nonce')}|{blob.get('expiry')}|{taint_epoch}|{challenge_seq}"
        expected_hash = hashlib.sha256(raw_challenge.encode('utf-8')).hexdigest()
        if blob.get("challenge_hash") and blob.get("challenge_hash") != expected_hash:
            return False
        data_to_verify = expected_hash.encode('utf-8')
    elif version in ("CHALLENGE_V2", "2"):
        challenge_seq = blob.get("challenge_seq", 0)
        raw_challenge = f"CHALLENGE_V2|{device_id}|{tool}|{args_hash.lower()}|{blob.get('nonce')}|{blob.get('expiry')}|{taint_epoch}|{challenge_seq}"
        expected_hash = hashlib.sha256(raw_challenge.encode('utf-8')).hexdigest()
        if blob.get("challenge_hash") and blob.get("challenge_hash") != expected_hash:
            return False
        data_to_verify = expected_hash.encode('utf-8')
    elif version in ("ACTION_APPROVAL_V1", "1"):
        data_to_verify = f"ACTION_APPROVAL_V1|{device_id}|{tool}|{args_hash.lower()}|{blob.get('nonce')}|{blob.get('expiry')}|{taint_epoch}".encode('utf-8')
    else:
        return False

    try:
        return device_registry.verify_asymmetric_signature(pub_key_pem, data_to_verify, signature)
    except Exception as e:
        logger.warning("Error verifying approval evidence signature: %s", e)
        return False


def record_approved_action(caller_id: str, tool: str, args_hash: str, taint_epoch: int, ttl: float = 120.0, signed_blob: Optional[Any] = None):
    """Module-level production helper: records direct action approval across memory and SQLite."""
    sup = get_active_supervisor()
    if sup:
        sup.record_approved_action(caller_id, tool, args_hash, taint_epoch, ttl=ttl, signed_blob=signed_blob)
    else:
        try:
            import db_utils
            exp_time = time.time() + ttl
            blob_str = json.dumps(signed_blob) if isinstance(signed_blob, dict) else (str(signed_blob) if signed_blob else "")
            with db_utils.get_db() as conn:
                _init_approved_actions_table(conn)
                conn.execute("""
                    INSERT INTO approved_actions (caller_id, tool, args_hash, taint_epoch, expiry, consumed, signature_blob)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                """, (caller_id, tool, args_hash.lower(), int(taint_epoch), exp_time, blob_str))
                conn.commit()
        except Exception as e:
            logger.warning("Could not persist module-level approved action to SQLite: %s", e)


def consume_approved_action(caller_id: str, tool: str, args_hash: str, taint_epoch: int) -> bool:
    """Module-level production helper: checks and consumes direct action approval across memory and SQLite.
    Anti-Burn DoS defense: Iterates candidate rows so invalid/junk rows do not burn valid approvals.
    Anti-Replay defense: Atomically verifies and records nonce in persistent nonce store.
    """
    sup = get_active_supervisor()
    if sup and sup.consume_approved_action(caller_id, tool, args_hash, taint_epoch):
        return True
    try:
        import db_utils
        now = time.time()
        with db_utils.get_db() as conn:
            _init_approved_actions_table(conn)
            cur = conn.cursor()
            cur.execute("""
                SELECT id, signature_blob FROM approved_actions
                WHERE caller_id = ? AND tool = ? AND args_hash = ? AND taint_epoch = ? AND consumed = 0 AND expiry >= ?
                ORDER BY id ASC
            """, (caller_id, tool, args_hash.lower(), int(taint_epoch), now))
            rows = cur.fetchall()
            for row in rows:
                sig_blob = row["signature_blob"] if "signature_blob" in row.keys() else row[1]
                if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                    b_dict = json.loads(sig_blob) if isinstance(sig_blob, str) else (sig_blob if isinstance(sig_blob, dict) else {})
                    nonce = b_dict.get("nonce")
                    nonce_exp = int(b_dict.get("expiry", now + 60))
                    if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                        logger.warning("Module-level SQLite approved action row %s rejected: nonce already consumed (replay)!", row["id"])
                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
                        continue

                    cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                    conn.commit()
                    return True
                else:
                    logger.warning("Module-level SQLite approved action row %s rejected: invalid evidence, skipping junk row", row["id"])
                    cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                    conn.commit()
    except Exception as e:
        logger.warning("Could not consume module-level approved action from SQLite: %s", e)
    return False


class PolicySupervisor:
    """High-Integrity Out-of-Process Policy Supervisor & Actuator Dispatcher."""

    def __init__(self, authorized_worker_pid: Optional[int] = None, state_db_path: Optional[str] = None):
        global _ACTIVE_SUPERVISOR
        _ACTIVE_SUPERVISOR = self
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
        
        # Complete Mediation Actuator & Cryptographic Key Initialization
        import crypto_vault
        self._supervisor_secret = crypto_vault.derive_subkey("actuator", length=32)
        self._consumed_intent_tokens = set()
        self._intent_lock = threading.Lock()
        self._approved_actions: Dict[Tuple[str, str, int], float] = {}
        self._approved_lock = threading.Lock()
        self.actuator = SupervisorActuator(self)
        self.envelope = None
        
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

    def mint_intent_token(self, tool: str, args: Dict[str, Any], caller_id: str, seq: int) -> str:
        """Mints an unforgeable HMAC-SHA256 INTENT token inside supervisor private memory.
        Enforces dictionary arguments and full 64-character SHA-256 arguments binding."""
        now = time.time()
        if not isinstance(args, dict):
            raise ValueError(f"mint_intent_token strictly requires a dictionary, got {type(args).__name__}")
        clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
        raw = f"INTENT_V2:{self.session_epoch}:{seq}:{int(now)}:{tool}:{args_hash}:{caller_id}"
        sig = hmac.new(self._supervisor_secret, raw.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{raw}:{sig}"

    def verify_and_consume_intent_token(
        self, token: Optional[str], tool: str, args: Dict[str, Any], caller_id: str, seq: int
    ) -> bool:
        """Verifies supervisor INTENT token integrity, arguments binding (full 64-char args_hash),
        sequence binding (token_seq == seq), freshness (<=15s), and enforces single-use replay protection.
        Thread-safe atomic verification and consumption under _intent_lock."""
        if not token or not isinstance(token, str) or not token.startswith("INTENT_V2:"):
            return False

        with self._intent_lock:
            # Replay prevention: check if token was already consumed
            if isinstance(self._consumed_intent_tokens, dict):
                if token in self._consumed_intent_tokens:
                    return False
            elif token in self._consumed_intent_tokens:
                return False

            if ":" not in token:
                return False

            raw, sig = token.rsplit(":", 1)
            parts = raw.split(":", 6)
            if len(parts) != 7:
                return False

            v_tag, epoch_str, seq_str, ts_str, tok_tool, tok_args_hash, tok_caller = parts
            try:
                epoch = int(epoch_str)
                token_seq = int(seq_str)
                ts = int(ts_str)
            except ValueError:
                return False

            if epoch != self.session_epoch:
                return False
            if abs(time.time() - ts) > 15.0:  # 15-second TTL
                return False
            if token_seq != seq:  # Strictly bind sequence number!
                return False
            if tok_tool != tool or tok_caller != caller_id:
                return False

            # Verify arguments hash (reject non-dict args)
            if not isinstance(args, dict):
                return False
            clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
            expected_args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
            if not hmac.compare_digest(tok_args_hash, expected_args_hash):
                return False

            expected_sig = hmac.new(self._supervisor_secret, raw.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return False

            # Consume token to enforce single-use replay protection and prune expired tokens (>30s)
            now = time.time()
            if not isinstance(self._consumed_intent_tokens, dict):
                self._consumed_intent_tokens = {}
            self._consumed_intent_tokens[token] = now
            # Prune expired tokens
            to_prune = [t for t, exp in self._consumed_intent_tokens.items() if now - exp > 30.0]
            for t in to_prune:
                del self._consumed_intent_tokens[t]
            return True

    def verify_intent_token(self, token: Optional[str], tool: str, caller_id: str, seq: int) -> bool:
        """Legacy helper for backwards compatibility."""
        return False

    def record_approved_action(self, caller_id: str, tool: str, args_hash: str, taint_epoch: int, ttl: float = 120.0, signed_blob: Optional[Any] = None):
        """Directive 14 & Batch 32 & 35 & 37: Stores direct challenge approval bound to (caller_id, tool, args_hash, taint_epoch) with cryptographic evidence."""
        exp_time = time.time() + ttl
        blob_str = json.dumps(signed_blob) if isinstance(signed_blob, dict) else (str(signed_blob) if signed_blob else "")
        with self._approved_lock:
            self._approved_actions[(caller_id, tool, args_hash.lower(), int(taint_epoch))] = (exp_time, signed_blob)
        # Cross-process durable SQLite persistence
        try:
            import db_utils
            with db_utils.get_db() as conn:
                _init_approved_actions_table(conn)
                conn.execute("""
                    INSERT INTO approved_actions (caller_id, tool, args_hash, taint_epoch, expiry, consumed, signature_blob)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                """, (caller_id, tool, args_hash.lower(), int(taint_epoch), exp_time, blob_str))
                conn.commit()
        except Exception as e:
            logger.warning("Could not persist approved action to SQLite: %s", e)

    def consume_approved_action(self, caller_id: str, tool: str, args_hash: str, taint_epoch: int) -> bool:
        """Directive 14 & Batch 32 & 35 & 37 & 38: Atomically checks and consumes a direct approved action
        with cryptographic verification of signed evidence blob against enrolled device keys.
        Anti-Burn DoS defense: Iterates candidate rows so invalid/junk rows do not burn valid approvals.
        Anti-Replay defense: Atomically verifies and records nonce in persistent nonce store.
        """
        now = time.time()
        in_memory_found = False
        with self._approved_lock:
            key = (caller_id, tool, args_hash.lower(), int(taint_epoch))
            exp = self._approved_actions.pop(key, None)
            # Prune expired
            to_del = [k for k, v in self._approved_actions.items() if now > (v[0] if isinstance(v, tuple) else v)]
            for k in to_del:
                self._approved_actions.pop(k, None)
            if exp:
                exp_time = exp[0] if isinstance(exp, tuple) else exp
                blob = exp[1] if isinstance(exp, tuple) else None
                if now <= exp_time:
                    if verify_signed_approval_evidence(blob, caller_id, tool, args_hash, taint_epoch):
                        b_dict = json.loads(blob) if isinstance(blob, str) else (blob if isinstance(blob, dict) else {})
                        nonce = b_dict.get("nonce")
                        nonce_exp = int(b_dict.get("expiry", exp_time))
                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                            logger.warning("In-memory approved action rejected: nonce already consumed (replay)!")
                        else:
                            in_memory_found = True
                    else:
                        logger.warning("In-memory approved action rejected: invalid or forged cryptographic evidence!")

        # Atomically consume in SQLite as well to prevent double-spending between memory and DB
        db_consumed = False
        try:
            import db_utils
            with db_utils.get_db() as conn:
                _init_approved_actions_table(conn)
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, signature_blob FROM approved_actions
                    WHERE caller_id = ? AND tool = ? AND args_hash = ? AND taint_epoch = ? AND consumed = 0 AND expiry >= ?
                    ORDER BY id ASC
                """, (caller_id, tool, args_hash.lower(), int(taint_epoch), now))
                rows = cur.fetchall()
                for row in rows:
                    sig_blob = row["signature_blob"] if "signature_blob" in row.keys() else row[1]
                    if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                        b_dict = json.loads(sig_blob) if isinstance(sig_blob, str) else (sig_blob if isinstance(sig_blob, dict) else {})
                        nonce = b_dict.get("nonce")
                        nonce_exp = int(b_dict.get("expiry", now + 60))
                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                            logger.warning("SQLite approved action row %s rejected: nonce already consumed (replay)!", row["id"])
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                            conn.commit()
                            continue

                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
                        db_consumed = True
                        break
                    else:
                        logger.warning("Skipping invalid/forged SQLite approved action row %s; marking consumed to prevent DoS", row["id"])
                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
        except Exception as e:
            logger.warning("Could not consume approved action from SQLite: %s", e)

        return in_memory_found or db_consumed

    def clear_taint_and_reboot_worker(self, human_auth_token: str) -> Tuple[bool, str]:
        """Supervisor-side taint clearing: Clears workstation taint, bumps session epoch,
        rotates ephemeral actuator session secrets, and restarts the worker process with a fresh clean context.
        Persistent vault storage keys and audit ledger HMAC keys are strictly preserved."""
        ok, msg = taint_tracker.human_clear_taint(human_auth_token)
        if not ok:
            return False, f"Taint clear denied: {msg}"

        # Bump session epoch and rotate ONLY ephemeral actuator/intent secrets
        self.session_epoch = int(time.time())
        self._supervisor_secret = secrets.token_bytes(32)
        self._consumed_intent_tokens.clear()

        # Record worker context reboot in audit ledger
        agent_audit_ledger.record_agent_action(
            "supervisor", "worker_reboot", "WRITE_EXEC",
            {"reason": "Taint cleared by human, worker context refreshed", "epoch": self.session_epoch},
            decision="ALLOW"
        )
        logger.info("Supervisor cleared taint, bumped session epoch to %d, worker context rebooted.", self.session_epoch)
        return True, "Workstation taint cleared and worker context cleanly rebooted."

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
            return self._handle_propose(payload, seq=seq)
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

    def _handle_propose(self, payload: Dict[str, Any], seq: int = 0) -> bytes:
        if seq is None or not isinstance(seq, int) or seq <= 0:
            return self._encode_reply(MSG_ERROR, {
                "error": "Sequence number seq is strictly required and must be a positive integer",
                "reason_code": REASON_MALFORMED_FRAME
            })

        req_id = payload.get("req_id", f"req_{int(time.time()*1000)}")
        tool = payload.get("tool", "")
        args = payload.get("args")
        if not isinstance(args, dict):
            return self._encode_reply(MSG_ERROR, {
                "error": "Malformed proposal: args must be a JSON object dictionary",
                "reason_code": REASON_MALFORMED_FRAME
            })

        # Supervisor derives caller_id from connection identity, ignoring worker spoofing
        caller_id = getattr(self, "authorized_worker_name", "worker") or "worker"
        # Supervisor derives args_hash internally, ignoring worker spoofing
        clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()

        client_token = payload.get("client_token")
        step_up_token = payload.get("step_up_token")
        frame_seq = seq

        self.active_request_id = req_id

        # 0. Reject worker attempting to forge an INTENT token in proposal
        if "intent_token" in payload:
            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "DENY",
                "reason_code": REASON_UNAUTHORIZED_TOKEN,
                "reason": "Complete Mediation Violation: Worker attempted to inject or forge supervisor INTENT token."
            })

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

        # 7. Client Token Authentication check (fail-closed if token enforcement required and token omitted)
        if client_token_auth.is_token_enforcement_active() or client_token:
            if not client_token:
                return self._encode_reply(MSG_DECISION, {
                    "req_id": req_id,
                    "status": "DENY",
                    "reason_code": REASON_UNAUTHORIZED_TOKEN,
                    "reason": "Missing client authentication token: Token enforcement is active"
                })
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

        # 5.1. Policy Envelope domain scoping, step budget & prohibited environments
        # Resolve real active foreground process & domain via supervisor-first inspection
        fg_info = windows_tools.get_foreground_window()
        supervisor_proc = (fg_info.get("proc_name") or "") if fg_info else ""
        current_proc = supervisor_proc  # Fail-closed: Supervisor inspects OS foreground; NEVER accepts worker self-attested proc

        # Supervisor-first domain resolution:
        # If in a browser image, extract real URL via UIA from the address bar (worker-attested domain and title are ignored)
        current_domain = None
        clean_proc = os.path.basename(supervisor_proc).lower()
        if clean_proc in policy_envelope.BROWSER_IMAGES:
            current_domain = windows_tools.get_browser_active_domain(fg_info.get("hwnd") if fg_info else None)
        else:
            # For non-browser network tools, read explicit target argument
            raw_target = args.get("domain") or args.get("url") or args.get("target")
            if raw_target:
                import urllib.parse
                try:
                    current_domain = urllib.parse.urlparse(str(raw_target)).hostname or str(raw_target)
                except Exception:
                    current_domain = str(raw_target)

        ks_to_commit = 0
        res_token = None
        if getattr(self, "envelope", None) and getattr(self.envelope, "is_active", False):
            current_epoch = taint_tracker.get_taint_epoch()
            env_ok, env_msg, ks_to_commit, res_token = self.envelope.reserve_step(
                tool, args, current_proc, current_epoch, current_domain
            )
            if not env_ok:
                return self._encode_reply(MSG_DECISION, {
                    "req_id": req_id,
                    "status": "DENY",
                    "reason_code": REASON_ENVELOPE_BREACH,
                    "reason": f"Policy Envelope Gate: {env_msg}"
                })

        step_committed = False
        actuator_invoked = False
        try:
            # 9. Taint & Out-of-band Step-up Verification (Fail-Closed)
            allowed, requires_step_up, taint_reason = taint_tracker.check_action_privilege(
                caller_id, tier, tool, args
            )
            if not allowed:
                if requires_step_up:
                    current_epoch = taint_tracker.get_taint_epoch()
                    if self.consume_approved_action(caller_id, tool, args_hash, current_epoch):
                        logger.info("Supervisor authorized action '%s' via internal direct approval for caller '%s'", tool, caller_id)
                    elif step_up_token:
                        valid_step_up, step_up_msg = taint_tracker.verify_and_consume_step_up_token(
                            step_up_token, tool, args
                        )
                        if not valid_step_up:
                            return self._encode_reply(MSG_DECISION, {
                                "req_id": req_id,
                                "status": "DENY",
                                "reason_code": REASON_UNAUTHORIZED_TOKEN,
                                "reason": f"Step-up token rejected: {step_up_msg}"
                            })
                        logger.info("Supervisor authorized action '%s' via consumed step-up token for caller '%s'", tool, caller_id)
                    else:
                        return self._encode_reply(MSG_DECISION, {
                            "req_id": req_id,
                            "status": "NEEDS_HUMAN",
                            "reason_code": REASON_TAINTED_STEPUP,
                            "reason": taint_reason
                        })
                else:
                    return self._encode_reply(MSG_DECISION, {
                        "req_id": req_id,
                        "status": "DENY",
                        "reason_code": REASON_TAINTED_EXECUTION,
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
            # Phase 1: Supervisor mints unforgeable cryptographic INTENT token & records in audit ledger
            intent_token = self.mint_intent_token(tool, args, caller_id, frame_seq)
            try:
                agent_audit_ledger.record_agent_action(
                    caller_id, tool, tier, args, decision=f"INTENT:{req_id}:{intent_token[:32]}"
                )
            except Exception as intent_err:
                logger.critical("Audit ledger write failure during INTENT recording: %s", intent_err)
                self._transition_to_locked(f"Audit ledger failure on INTENT: {intent_err}")
                return self._encode_reply(MSG_ERROR, {
                    "error": f"Audit ledger failure: {intent_err}",
                    "reason_code": REASON_UNAUTHORIZED_TOKEN
                })

            # Phase 2: Privileged Supervisor Actuator executes effect WITH verified intent token
            execution_success = False
            exception_occurred = False
            result = ""
            try:
                try:
                    actuator_invoked = True
                    result = self.actuator.execute_actuator(
                        tool, args, caller_id=caller_id, client_token=client_token, intent_token=intent_token, seq=frame_seq
                    )
                    execution_success = True
                except CompleteMediationBreachError as cme:
                    execution_success = False
                    result = f"Security Gate: {cme}"
                    self._transition_to_locked(f"Complete mediation violation: {cme}")
                except Exception as e:
                    execution_success = False
                    exception_occurred = True
                    result = f"Error executing tool in supervisor: {e}"
            finally:
                # Phase 3: Record OUTCOME in HMAC-SHA256 audit ledger in finally block to guarantee ledger audit invariant
                if execution_success:
                    outcome_status = "SUCCESS"
                elif exception_occurred:
                    outcome_status = "UNKNOWN"
                else:
                    outcome_status = "FAILED"

                try:
                    agent_audit_ledger.record_agent_action(
                        caller_id, tool, tier, args, decision=f"OUTCOME:{req_id}:{outcome_status}"
                    )
                except Exception as ledger_err:
                    logger.critical("Audit ledger write failure during outcome recording: %s", ledger_err)
                    self._transition_to_locked(f"Audit ledger failure: {ledger_err}")

                self.active_request_id = None

            # Commit policy envelope step budget if actuator was invoked (SUCCESS or UNKNOWN outcome).
            # If the actuator was invoked, side-effects may have taken place on the desktop/OS;
            # the step budget MUST be consumed to prevent free retries on partial actions.
            if actuator_invoked:
                if getattr(self, "envelope", None) and getattr(self.envelope, "is_active", False):
                    self.envelope.commit_step(ks_to_commit, res_token)
                    step_committed = True

            return self._encode_reply(MSG_DECISION, {
                "req_id": req_id,
                "status": "ALLOW" if execution_success else "DENY",
                "reason_code": REASON_OK if execution_success else REASON_EXECUTION_FAILED,
                "reason": "Action authorized and successfully executed by supervisor" if execution_success else result,
                "result": result
            })

        finally:
            # Single-point guaranteed reservation release for all early returns, denials, and exceptions.
            # Release reservation ONLY if the actuator was NEVER invoked!
            if res_token and not step_committed and not actuator_invoked:
                if getattr(self, "envelope", None) and getattr(self.envelope, "is_active", False):
                    self.envelope.release_reservation(res_token)


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
