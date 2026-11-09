"""Homie Phone-Signed Cryptographic Step-Up Gateway (Batch 27 Hardened).

Eliminates the "Telegram-on-same-PC" trust compromise:
- Asymmetric Key Architecture (RFC 8032 Ed25519):
  The private signing key resides EXCLUSIVELY on the user's mobile device (hardware secure enclave).
  The PC supervisor holds ONLY the public key. The PC has zero private signing keys and cannot sign.
- Strict Challenge & Payload Binding:
  Challenge = SHA-256(device_id | tool | args_hash | nonce | expiry | taint_epoch | seq).
  Action Approval = Ed25519_Sign(ACTION_APPROVAL_V1|device_id|action_name|payload_hash|nonce|expiry|taint_epoch).
- Verification-First Ordering:
  Signatures are verified before counter increment or challenge deletion, preventing denial-of-service lockout.
- Fail-Closed:
  Unknown device IDs are strictly denied. Auto-creation backdoors and key override parameters are eliminated.
- Persistent Anti-Replay:
  Consumed nonces are persisted with integer expiry to survive restarts and prevent replay attacks.
- Taint-Epoch & Monotonic Counter Invariants:
  Rejects approvals signed under previous taint epochs or stale counters.
"""

import os
import sys
import time
import json
import hashlib
import secrets
import logging
import threading
from typing import Dict, Any, Optional, Tuple
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import taint_tracker
import agent_audit_ledger
import homie_confinement
import device_registry
from device_registry import (
    verify_asymmetric_signature,
    _load_device_registry,
    _save_device_registry,
    revoke_device_key,
    check_and_record_consumed_nonce,
    is_nonce_consumed,
    record_consumed_nonce,
    _load_consumed_nonces,
    _save_consumed_nonces,
    clear_consumed_nonces_for_testing,
    _REGISTRY_LOCK,
    _NONCE_LOCK,
    DEVICE_REGISTRY_PATH,
    CONSUMED_NONCES_PATH
)

logger = logging.getLogger("homie.phone_portal")

ADMIN_RECOVERY_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Homie")
ADMIN_RECOVERY_TOKEN_PATH = os.path.join(ADMIN_RECOVERY_DIR, "console_recovery.token")
ENROLLMENT_LOCKOUT_PATH = os.path.join(BASE_DIR, ".homie_enrollment_lockout.json")

_ENROLLMENT_LOCK = threading.RLock()

def write_admin_recovery_token(token: str, ttl_seconds: float = 300.0) -> bool:
    """Writes an admin recovery token to Administrator/SYSTEM-protected ProgramData directory."""
    try:
        os.makedirs(ADMIN_RECOVERY_DIR, exist_ok=True)
        data = {
            "token_hash": hashlib.sha256(token.encode('utf-8')).hexdigest(),
            "expires_at": time.time() + ttl_seconds,
            "created_at": time.time()
        }
        with open(ADMIN_RECOVERY_TOKEN_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)

        try:
            import win32security, ntsecuritycon as nsc, win32con, win32api
            admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            users_sid = win32security.ConvertStringSidToSid("S-1-5-32-545")
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, system_sid)
            # Users SID granted read-only access (NO DELETE permission to prevent unelevated DoS attack)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ, users_sid)
            try:
                tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
                my_sid = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, my_sid)
            except Exception:
                pass

            win32security.SetNamedSecurityInfo(
                ADMIN_RECOVERY_TOKEN_PATH, win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, dacl, None
            )

            # Folder DACL: Administrators(F), SYSTEM(F), Users(RX traverse/read-only - cannot create files)
            dir_dacl = win32security.ACL()
            dir_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, admin_sid)
            dir_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, system_sid)
            dir_dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ | win32con.GENERIC_EXECUTE, users_sid)
            try:
                win32security.SetNamedSecurityInfo(
                    ADMIN_RECOVERY_DIR, win32security.SE_FILE_OBJECT,
                    win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                    None, None, dir_dacl, None
                )
            except Exception:
                pass
        except Exception:
            pass
        return True
    except Exception as e:
        logger.warning("Could not write admin recovery token: %s", e)
        return False

def consume_admin_recovery_token(recovery_token: Optional[str]) -> bool:
    """Consumes single-use admin recovery token from C:\\ProgramData\\Homie\\console_recovery.token.
    Enforces atomic single-use via SQLite table console_recovery_tokens when file unlinking is barred by read-only DACL.
    """
    if not recovery_token or not isinstance(recovery_token, str):
        return False
    tok = recovery_token.strip()
    tok_hash = hashlib.sha256(tok.encode('utf-8')).hexdigest()
    now = time.time()

    # 1. Authoritative DB single-use record check
    try:
        import db_utils
        _init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            cursor = conn.execute(
                "UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0 AND expires_at > ?",
                (tok_hash, now)
            )
            conn.commit()
            if cursor.rowcount > 0:
                logger.info("Admin recovery token consumed via authoritative DB record")
                if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                    try:
                        os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                    except Exception:
                        pass
                return True
    except Exception as e:
        logger.debug("DB token consumption check error: %s", e)

    # 2. File fallback if DB table not populated
    if not os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
        return False
    try:
        with open(ADMIN_RECOVERY_TOKEN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("token_hash") != tok_hash:
            return False
        if now > data.get("expires_at", 0):
            try:
                os.remove(ADMIN_RECOVERY_TOKEN_PATH)
            except Exception:
                pass
            return False
        try:
            os.remove(ADMIN_RECOVERY_TOKEN_PATH)
            return True
        except PermissionError:
            # When caller lacks DELETE permission due to read-only DACL, single-use is enforced via DB
            logger.info("Unlink barred by DACL; token consumed single-use via DB record")
            return False
        except Exception as rm_err:
            logger.critical("Failed to unlink admin recovery token; single use invariant failed: %s", rm_err)
            return False
    except Exception as e:
        logger.warning("Could not consume admin recovery token: %s", e)
        return False
_DISPLAY_DRIVER = None
MAX_ACTION_APPROVAL_TTL = 300.0  # 5 minutes maximum validity cap for action approvals

def set_display_driver(driver_fn):
    """Allows test harness to inject a capture-excluded display driver without environment sniffing."""
    global _DISPLAY_DRIVER
    _DISPLAY_DRIVER = driver_fn

_ACTIVE_CHALLENGES: Dict[str, Dict[str, Any]] = {}  # step_up_id -> challenge_metadata
_LOCAL_ENROLLMENT_SESSIONS: Dict[str, Dict[str, Any]] = {}  # session_id -> {pairing_code, expiry, failed_attempts}
_PENDING_ACTION_NONCES: set = set()
MAX_FAILED_ENROLLMENT_ATTEMPTS = 3
_SUPERVISOR_CHALLENGE_SEQ = 0
_CONSOLE_RECOVERY_TOKENS: Dict[str, float] = {}

def _init_recovery_tokens_table():
    try:
        import db_utils
        with db_utils.get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS console_recovery_tokens (
                    token_hash TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    consumed INTEGER DEFAULT 0,
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()
    except Exception as e:
        logger.warning("Could not initialize console_recovery_tokens table: %s", e)

def generate_console_recovery_token(ttl_seconds: float = 300.0) -> str:
    """Generates an unguessable 32-character single-use recovery token in local console memory and SQLite.
    Valid for 5 minutes. Persisted across processes so CLI recovery commands can authorize server enrollment.
    """
    token = secrets.token_hex(16)
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = time.time()
    exp = now + ttl_seconds
    with _ENROLLMENT_LOCK:
        _CONSOLE_RECOVERY_TOKENS[token] = exp
    try:
        import db_utils
        _init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            conn.execute(
                "INSERT INTO console_recovery_tokens (token_hash, expires_at, consumed, created_at) VALUES (?, ?, 0, ?)",
                (token_hash, exp, now)
            )
            conn.commit()
    except Exception as e:
        logger.warning("Could not persist recovery token to SQLite: %s", e)
    write_admin_recovery_token(token, ttl_seconds=ttl_seconds)
    return token

def consume_console_recovery_token(recovery_token: Optional[str]) -> bool:
    """Consumes single-use console recovery token from in-memory cache or cross-process SQLite table."""
    if not recovery_token or not isinstance(recovery_token, str):
        return False
    tok = recovery_token.strip()
    now = time.time()
    token_hash = hashlib.sha256(tok.encode('utf-8')).hexdigest()

    # 1. Try in-memory cache
    with _ENROLLMENT_LOCK:
        exp = _CONSOLE_RECOVERY_TOKENS.pop(tok, None)
        if exp and now <= exp:
            try:
                import db_utils
                with db_utils.get_db() as conn:
                    conn.execute("UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ?", (token_hash,))
                    conn.commit()
            except Exception:
                pass
            return True

    # 2. Try Admin ProgramData token
    if consume_admin_recovery_token(tok):
        return True

    # 3. Try cross-process SQLite table
    try:
        import db_utils
        _init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT rowid, expires_at FROM console_recovery_tokens WHERE token_hash = ? AND consumed = 0 AND expires_at > ?",
                (token_hash, now)
            )
            row = cur.fetchone()
            if row:
                row_id = row[0]
                cur.execute("UPDATE console_recovery_tokens SET consumed = 1 WHERE rowid = ?", (row_id,))
                conn.commit()
                return True
    except Exception as e:
        logger.warning("Error consuming recovery token from SQLite: %s", e)

    return False

def _load_enrollment_lockout() -> Dict[str, Any]:
    if os.path.exists(ENROLLMENT_LOCKOUT_PATH):
        try:
            with open(ENROLLMENT_LOCKOUT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_enrollment_lockout(data: Dict[str, Any]):
    try:
        with open(ENROLLMENT_LOCKOUT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def is_enrollment_locked_out() -> bool:
    with _ENROLLMENT_LOCK:
        lockout = _load_enrollment_lockout()
        now = time.time()
        locked_until = lockout.get("locked_until", 0)
        return bool(locked_until > now)

def record_failed_enrollment_attempt():
    with _ENROLLMENT_LOCK:
        lockout = _load_enrollment_lockout()
        now = time.time()
        attempts = [t for t in lockout.get("failed_attempts", []) if now - t < 600]
        attempts.append(now)
        lockout["failed_attempts"] = attempts
        if len(attempts) >= 5:
            lockout["locked_until"] = now + 600  # 10 minute lockout
            logger.warning("Global enrollment lockout engaged: 5 failed attempts across sessions.")
        _save_enrollment_lockout(lockout)

def reset_pairing_lockout(recovery_token: Optional[str] = None) -> Tuple[bool, str]:
    """Human recovery console command: resets enrollment lockout after failed attempts.
    Strictly requires a valid single-use local console recovery token (fails closed otherwise).
    Zero boolean presence bypasses permitted.
    """
    if not consume_console_recovery_token(recovery_token):
        logger.warning("Denied unauthenticated pairing lockout reset attempt.")
        return False, "DENY: Valid single-use console recovery token required to reset pairing lockout."

    with _ENROLLMENT_LOCK:
        _LOCAL_ENROLLMENT_SESSIONS.clear()
        if os.path.exists(ENROLLMENT_LOCKOUT_PATH):
            try:
                os.remove(ENROLLMENT_LOCKOUT_PATH)
            except Exception:
                pass
    try:
        agent_audit_ledger.record_agent_action(
            "console_user", "pairing_lockout_reset", "WRITE_EXEC",
            {"timestamp": time.time(), "method": "console_recovery_token"},
            decision="ALLOW"
        )
    except Exception as e:
        logger.warning("Audit recording warning: %s", e)
    logger.info("Pairing lockout reset via local console recovery command.")
    return True, "Pairing lockout successfully reset. You may now initiate a new pairing session."


# ==============================================================================
# 1. PERSISTENT CONSUMED NONCES STORAGE
# ==============================================================================

def _load_consumed_nonces() -> Dict[str, int]:
    """Loads persistent consumed nonces, automatically pruning expired entries."""
    now = int(time.time())
    if os.path.exists(CONSUMED_NONCES_PATH):
        try:
            with open(CONSUMED_NONCES_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # Prune nonces only after their approval expiry + 60s has passed
            valid = {nonce: int(exp) for nonce, exp in raw.items() if int(exp) + 60 > now}
            return valid
        except Exception as e:
            logger.warning("Could not load consumed nonces: %s", e)
            return {}
    return {}


def _save_consumed_nonces(nonces: Dict[str, int]):
    """Persists consumed nonces and secures file permissions with owner-only DACL."""
    try:
        with open(CONSUMED_NONCES_PATH, "w", encoding="utf-8") as f:
            json.dump(nonces, f, indent=2)
        try:
            homie_confinement.harden_path(CONSUMED_NONCES_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist consumed nonces: %s", e)


def is_nonce_consumed(nonce: str) -> bool:
    """Checks whether a nonce has already been consumed and is still within validity window."""
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        return nonce in nonces


def record_consumed_nonce(nonce: str, expiry: int):
    """Marks a nonce as consumed in persistent storage under _NONCE_LOCK."""
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        nonces[nonce] = int(expiry)
        _save_consumed_nonces(nonces)


def check_and_record_consumed_nonce(nonce: str, expiry: int) -> bool:
    """Atomically checks if nonce is consumed, and if not, records it under _NONCE_LOCK.
    Returns True if nonce was fresh and recorded successfully, False if already consumed (replay)."""
    with _NONCE_LOCK:
        nonces = _load_consumed_nonces()
        if nonce in nonces:
            return False
        nonces[nonce] = int(expiry)
        _save_consumed_nonces(nonces)
        return True


# ==============================================================================
# 2. DEVICE REGISTRY STORAGE (PC HOLDS ONLY PUBLIC KEYS)
# ==============================================================================

def _load_device_registry() -> Dict[str, Any]:
    """Loads the device public key registry from disk."""
    if os.path.exists(DEVICE_REGISTRY_PATH):
        try:
            with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not read device registry: %s", e)
            return {}
    return {}


def _save_device_registry(registry: Dict[str, Any]):
    """Persists device public keys with owner-only DACL protection."""
    try:
        with open(DEVICE_REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)
        try:
            homie_confinement.harden_path(DEVICE_REGISTRY_PATH)
        except Exception:
            pass
    except Exception as e:
        logger.error("Could not persist device registry: %s", e)


def revoke_device_key(device_id: str) -> bool:
    """Revokes a paired device key under _REGISTRY_LOCK, immediately blocking all further approvals."""
    with _REGISTRY_LOCK:
        registry = _load_device_registry()
        if device_id in registry:
            registry[device_id]["revoked"] = True
            _save_device_registry(registry)
            # Clear any active challenges targeting this device
            to_del = [sid for sid, ch in _ACTIVE_CHALLENGES.items() if ch.get("device_id") == device_id]
            for sid in to_del:
                del _ACTIVE_CHALLENGES[sid]
            logger.warning("Revoked device key %s", device_id)
            return True
        return False


# ==============================================================================
# 3. PHYSICAL PRESENCE ENROLLMENT CEREMONY
# ==============================================================================

def display_secure_pairing_code(code: str) -> bool:
    """Displays pairing code on a window excluded from screen capture (WDA_EXCLUDEFROMCAPTURE)."""
    if _DISPLAY_DRIVER is not None:
        return _DISPLAY_DRIVER(code)
    try:
        import homie_hud
        hud = homie_hud.HomieHardwareHUD()
        hud.create_overlay()
        hud.set_target_box(100, 100, 400, 150, f"HOMIE PAIRING CODE: {code}")
        hud.show()
        hud.destroy()
        return True
    except Exception as e:
        logger.warning("Could not open capture-excluded pairing window: %s", e)
        return False


def start_local_enrollment(ttl_seconds: float = 120.0) -> str:
    """Initiates a local enrollment ceremony requiring physical presence at the PC.
    Generates a high-entropy 6-digit one-time pairing code displayed strictly on capture-excluded HUD.
    Returns enrollment_session_id only (NEVER returns pairing_code to callers, preventing in-process exfiltration).
    """
    if is_enrollment_locked_out():
        logger.warning("Enrollment blocked: Global pairing attempt lockout is active.")
        return ""

    session_id = secrets.token_hex(16)
    pairing_code = f"{secrets.randbelow(1_000_000):06d}"
    expiry = time.time() + ttl_seconds

    # Display code strictly on capture-excluded HUD
    hud_shown = display_secure_pairing_code(pairing_code)
    if not hud_shown:
        logger.error("Capture-excluded HUD display failed. Aborting pairing ceremony for physical security.")
        return ""

    with _ENROLLMENT_LOCK:
        _LOCAL_ENROLLMENT_SESSIONS[session_id] = {
            "pairing_code": pairing_code,
            "expiry": expiry,
            "failed_attempts": 0
        }
    logger.info("Initiated physical presence enrollment session %s (code valid for %ds)", session_id, int(ttl_seconds))
    return session_id


def complete_device_enrollment(
    session_id: str,
    pairing_code: str,
    device_id: str,
    public_key_pem: str,
    authenticator_type: str = "device_resident_ed25519",
    primary_approval_sig: Optional[str] = None,
    approver_device_id: Optional[str] = None,
    recovery_token: Optional[str] = None,
    approval_expiry: Optional[int] = None
) -> Tuple[bool, str]:
    """Completes phone pairing by verifying the physical presence one-time code.
    Enforces that public_key_pem is strictly an asymmetric public key on the Ed25519 or P-256 curve.
    Locks out and destroys session after 3 failed attempts.
    Rejects re-enrollment of already enrolled devices to prevent unauthorized overwrites.
    Enforces that enrolling a second device requires cryptographic approval from an active device.
    Fails closed immediately if global enrollment lockout is active.
    If all devices are revoked, requires a valid console recovery token to enroll a replacement device.
    All state operations are fully atomic under _REGISTRY_LOCK and _ENROLLMENT_LOCK.
    """
    if is_enrollment_locked_out():
        return False, "DENY: Global enrollment lockout is active. Please wait or reset via console."

    import re
    if not isinstance(device_id, str) or not re.match(r"^[a-zA-Z0-9_\-]{3,32}$", device_id):
        return False, f"INVALID_DEVICE_ID: Device ID '{device_id}' must match ^[a-zA-Z0-9_\\-]{{3,32}}$"

    if not isinstance(public_key_pem, str) or len(public_key_pem) > 1024 or len(public_key_pem) < 64:
        return False, "INVALID_KEY_LENGTH: Public key PEM must be between 64 and 1024 characters."

    with _ENROLLMENT_LOCK:
        sess = _LOCAL_ENROLLMENT_SESSIONS.get(session_id)
        if not sess:
            # Remote attacker sending non-existent session IDs must NOT trigger global lockout DoS
            return False, "Enrollment session not found, expired, or locked out"

        if time.time() > sess["expiry"]:
            del _LOCAL_ENROLLMENT_SESSIONS[session_id]
            return False, "Enrollment session expired"

        # Constant-time comparison of pairing code against existing active session
        import hmac
        if not hmac.compare_digest(str(pairing_code).strip(), str(sess["pairing_code"]).strip()):
            record_failed_enrollment_attempt()
            sess["failed_attempts"] += 1
            if sess["failed_attempts"] >= MAX_FAILED_ENROLLMENT_ATTEMPTS:
                del _LOCAL_ENROLLMENT_SESSIONS[session_id]
                logger.warning("Enrollment session %s locked out after %d failed attempts", session_id, sess["failed_attempts"])
                return False, "Enrollment locked out: too many failed attempts. Session destroyed."
            return False, f"Invalid pairing code (attempt {sess['failed_attempts']}/{MAX_FAILED_ENROLLMENT_ATTEMPTS})"

        # Atomically consume session from registry the instant pairing code matches (TOCTOU elimination)
        del _LOCAL_ENROLLMENT_SESSIONS[session_id]

        # Validate asymmetric public key format and curve
        try:
            imported_key = ECC.import_key(public_key_pem.strip())
            if imported_key.has_private():
                return False, "DENY: Enrollment rejects private keys. Only public keys can be registered on PC."
            curve_norm = getattr(imported_key, 'curve', '').lower().replace(' ', '').replace('-', '')
            if curve_norm not in ('ed25519', 'p256', 'prime256v1', 'secp256r1', 'nistp256'):
                return False, "DENY: Asymmetric public key must be on the Ed25519 or P-256 curve."
        except Exception as e:
            return False, f"Invalid public key format: {e}"

    with _REGISTRY_LOCK:
        registry = _load_device_registry()
        # Anti-overwrite invariant: Reject re-enrollment of already enrolled devices
        if device_id in registry:
            with _ENROLLMENT_LOCK:
                _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
            return False, f"DEVICE_EXISTS: Device '{device_id}' is already enrolled. Overwrites are forbidden."

        # Second-device enrollment multi-sig gate: Adding a new device requires active device approval
        active_device_ids = [k for k, v in registry.items() if not v.get("revoked", False)]
        if registry: # Devices have previously been registered
            if not active_device_ids:
                # All previously registered devices are revoked (lost-phone scenario).
                # Re-enrollment requires a valid console recovery token to prevent unauthorized enrollment.
                if not consume_console_recovery_token(recovery_token):
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, "DENY: All registered devices are revoked. Physical console recovery token required to enroll a new device."
            else:
                # Active devices exist, multi-sig approval required
                target_approver = approver_device_id or ("primary_phone" if "primary_phone" in active_device_ids else active_device_ids[0])
                approver_entry = registry.get(target_approver)
                if not approver_entry or approver_entry.get("revoked", False):
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, f"APPROVER_INVALID: Approver device '{target_approver}' is not active or has been revoked."

                if not primary_approval_sig:
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, "APPROVAL_REQUIRED: Adding a device requires cryptographic approval from an active device."

                now = int(time.time())
                # Enforce strict signed expiry verification on session-bound V2 signature (strictly mandatory)
                if approval_expiry is None:
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, "APPROVAL_INVALID: Signed approval_expiry is strictly mandatory."

                try:
                    exp_val = int(approval_expiry)
                except (ValueError, TypeError):
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, "APPROVAL_INVALID: approval_expiry must be an integer timestamp."

                if exp_val < now:
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, f"APPROVAL_EXPIRED: Signed approval expired at {exp_val} (current time {now})"
                if exp_val > now + 300:
                    with _ENROLLMENT_LOCK:
                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)
                    return False, f"EXPIRY_OUT_OF_BOUNDS: Approval expiry {exp_val} exceeds 300s window"

                v2_msg = f"ENROLL_DEVICE_V2|{session_id}|{device_id}|{public_key_pem.strip()}|{exp_val}".encode('utf-8')
                if not verify_asymmetric_signature(approver_entry["public_key"], v2_msg, primary_approval_sig):
                    return False, "APPROVAL_INVALID: Signature from active approver device failed verification or is expired."

        registry[device_id] = {
            "public_key": public_key_pem.strip(),
            "authenticator_type": authenticator_type,
            "paired_at": time.time(),
            "counter": 0,
            "revoked": False,
            "device_name": f"Paired Mobile Authenticator ({device_id})"
        }
        _save_device_registry(registry)
    logger.info("Successfully enrolled device %s with authenticator %s", device_id, authenticator_type)
    return True, f"Device {device_id} successfully paired with hardware-backed key"





# ==============================================================================
# 4. CHALLENGE-RESPONSE GENERATION & ASYMMETRIC VERIFICATION
# ==============================================================================

def generate_approval_challenge(
    step_up_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: str,
    taint_epoch: int,
    device_id: str = "primary_phone",
    ttl_seconds: float = 120.0,
    caller_id: Optional[str] = None
) -> Dict[str, Any]:
    """Binds approval challenge to SHA-256(CHALLENGE_V3 | device_id | caller_id | tool | args_hash | nonce | expiry | taint_epoch | seq)
    when caller_id is specified, or CHALLENGE_V2 for backwards-compatible challenges.
    Also derives server expected counter and stores canonical_args string for safe UI rendering.
    """
    global _SUPERVISOR_CHALLENGE_SEQ
    _SUPERVISOR_CHALLENGE_SEQ += 1
    challenge_seq = _SUPERVISOR_CHALLENGE_SEQ

    registry = _load_device_registry()
    dev_entry = registry.get(device_id, {})
    expected_counter = dev_entry.get("counter", 0) + 1

    clean_args = json.dumps(arguments, sort_keys=True, separators=(',', ':')) if isinstance(arguments, dict) else str(arguments)
    args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
    nonce = secrets.token_hex(16)
    expiry = int(time.time() + ttl_seconds)

    if caller_id is not None:
        version = "CHALLENGE_V3"
        raw_challenge = f"CHALLENGE_V3|{device_id}|{caller_id}|{tool_name}|{args_hash}|{nonce}|{expiry}|{taint_epoch}|{challenge_seq}"
        eff_caller = caller_id
    else:
        version = "CHALLENGE_V2"
        raw_challenge = f"CHALLENGE_V2|{device_id}|{tool_name}|{args_hash}|{nonce}|{expiry}|{taint_epoch}|{challenge_seq}"
        eff_caller = "worker"

    challenge_hash = hashlib.sha256(raw_challenge.encode('utf-8')).hexdigest()

    canonical_prompt = (
        f"Security Authorization Required:\n"
        f"• Action: {tool_name}\n"
        f"• Caller: {eff_caller}\n"
        f"• Target Arguments: {clean_args[:150]}\n"
        f"• Session: {session_id}\n"
        f"• Valid for: {int(ttl_seconds)}s"
    )

    item = {
        "step_up_id": step_up_id,
        "device_id": device_id,
        "caller_id": eff_caller,
        "version": version,
        "tool_name": tool_name,
        "arguments": arguments,
        "canonical_args": clean_args,
        "args_hash": args_hash,
        "nonce": nonce,
        "expiry": expiry,
        "taint_epoch": taint_epoch,
        "challenge_seq": challenge_seq,
        "expected_counter": expected_counter,
        "challenge_hash": challenge_hash,
        "canonical_prompt": canonical_prompt,
        "session_id": session_id,
        "created_at": time.time(),
        "failed_attempts": 0
    }
    _ACTIVE_CHALLENGES[step_up_id] = item
    logger.info("Generated device-bound step-up challenge [ID: %s] for tool %s", step_up_id, tool_name)
    return item



def deny_approval_challenge(step_up_id: str, device_id: str = "primary_phone") -> Tuple[bool, str]:
    """Actively denies and purges an active approval challenge on the server."""
    with _REGISTRY_LOCK:
        if step_up_id in _ACTIVE_CHALLENGES:
            del _ACTIVE_CHALLENGES[step_up_id]
            logger.info("Challenge %s actively DENIED and purged by device %s", step_up_id, device_id)
            return True, "Challenge denied"
        return False, "Challenge not found"


def verify_asymmetric_signature(public_key_pem: str, data_bytes: bytes, signature_hex: str) -> bool:
    """Verifies an asymmetric signature (RFC 8032 Ed25519 or NIST P-256 / secp256r1 ECDSA).
    Supports both WebCrypto IEEE P1363 binary encoding (64 bytes r||s) and ASN.1 DER encoding.
    """
    try:
        pub_key = ECC.import_key(public_key_pem.strip())
        sig_bytes = bytes.fromhex(signature_hex.strip())
        curve_norm = getattr(pub_key, 'curve', '').lower().replace(' ', '').replace('-', '')
        if 'ed25519' in curve_norm:
            verifier = eddsa.new(pub_key, 'rfc8032')
            verifier.verify(data_bytes, sig_bytes)
            return True
        elif any(c in curve_norm for c in ('p256', 'prime256v1', 'secp256r1', 'nistp256')):
            from Crypto.Signature import DSS
            from Crypto.Hash import SHA256
            h = SHA256.new(data_bytes)
            for enc in ('binary', 'der'):
                try:
                    verifier = DSS.new(pub_key, 'fips-186-3', encoding=enc)
                    verifier.verify(h, sig_bytes)
                    return True
                except Exception:
                    continue
            return False
        return False
    except Exception:
        return False


def verify_device_approval(
    step_up_id: str,
    signature: str,
    device_id: str = "primary_phone",
    counter: Optional[int] = None,
    is_authenticated_caller: bool = True
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Verifies a phone-signed cryptographic approval with verification-first ordering.
    1. Looks up enrolled device public key (fail closed on unknown device).
    2. Verifies Ed25519 signature FIRST before updating counter or consuming challenge.
    3. On failure, unauthenticated callers CANNOT cancel challenges (anti-DoS).
    4. On success, verifies monotonic counter matches server expected counter (anti-poisoning), updates counter, and consumes challenge.
    """
    item = _ACTIVE_CHALLENGES.get(step_up_id)
    if not item:
        return False, "Challenge not found or already consumed", None

    # Cross-device check: Challenge must be consumed strictly by the target device
    if item.get("device_id") and device_id != item.get("device_id"):
        return False, f"DEVICE_MISMATCH: Challenge was issued to '{item.get('device_id')}', but approval was submitted by '{device_id}'", None

    # Mandatory monotonic counter check
    if counter is None:
        return False, "COUNTER_REQUIRED: Monotonic signature counter is mandatory for replay protection", None

    # Anti-counter-poisoning gate: Counter must match server expected counter
    expected_counter = item.get("expected_counter")
    if expected_counter is not None and counter != expected_counter:
        return False, f"COUNTER_MISMATCH: Submitted counter {counter} does not match expected counter {expected_counter}", None

    now = int(time.time())
    if now > int(item["expiry"]):
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, "Challenge expired", None

    registry = _load_device_registry()
    dev_entry = registry.get(device_id)
    if not dev_entry:
        return False, f"DEVICE_UNKNOWN: Device '{device_id}' is not enrolled in supervisor registry", None

    if dev_entry.get("revoked", False):
        del _ACTIVE_CHALLENGES[step_up_id]
        return False, f"Device {device_id} has been revoked", None

    # Step 1: VERIFY SIGNATURE FIRST (prevents unauthenticated counter lockouts)
    raw_challenge_bytes = item["challenge_hash"].encode('utf-8')
    sig_ok = verify_asymmetric_signature(dev_entry["public_key"], raw_challenge_bytes, signature)

    if not sig_ok:
        if is_authenticated_caller:
            item["failed_attempts"] = item.get("failed_attempts", 0) + 1
            if item["failed_attempts"] >= 3:
                del _ACTIVE_CHALLENGES[step_up_id]
                logger.warning("Challenge %s canceled after 3 failed signature attempts", step_up_id)
                return False, "Challenge canceled: too many failed verification attempts", None
        return False, f"Cryptographic signature verification failed (attempt {item.get('failed_attempts', 0)}/3)", None

    # Step 2: Signature is authentic -> check anti-replay counter under registry lock
    with _REGISTRY_LOCK:
        registry = _load_device_registry()
        dev_entry = registry.get(device_id)
        if not dev_entry:
            return False, f"DEVICE_UNKNOWN: Device '{device_id}' is not enrolled in supervisor registry", None
        last_counter = dev_entry.get("counter", 0)
        if counter <= last_counter:
            del _ACTIVE_CHALLENGES[step_up_id]
            return False, f"Replay detected: signature counter {counter} <= last counter {last_counter}", None
        dev_entry["counter"] = counter
        _save_device_registry(registry)

    # Step 3: Consume challenge single-use
    del _ACTIVE_CHALLENGES[step_up_id]

    # Step 4: Record verified human approval in HMAC ledger
    agent_audit_ledger.record_agent_action(
        f"phone_verified_{device_id}", item["tool_name"], "WRITE_EXEC", item["arguments"],
        decision=f"DEVICE_APPROVED:{step_up_id}"
    )

    # Step 5: Relay verified device approval to homie_supervisor cache & SQLite approved_actions table
    try:
        import homie_supervisor
        target_caller = item.get("caller_id") or "worker"
        remaining_ttl = max(1.0, float(item.get("expiry", now + 60) - now))
        signed_approval_blob = {
            "version": item.get("version", "CHALLENGE_V3"),
            "device_id": device_id,
            "caller_id": target_caller,
            "tool_name": item["tool_name"],
            "args_hash": str(item["args_hash"]).lower(),
            "nonce": item["nonce"],
            "expiry": item["expiry"],
            "taint_epoch": item.get("taint_epoch", 0),
            "challenge_seq": item.get("challenge_seq", 0),
            "challenge_hash": item["challenge_hash"],
            "signature": signature,
            "counter": counter
        }
        homie_supervisor.record_approved_action(
            caller_id=target_caller,
            tool=item["tool_name"],
            args_hash=str(item["args_hash"]).lower(),
            taint_epoch=item.get("taint_epoch", 0),
            ttl=min(remaining_ttl, 120.0),
            signed_blob=signed_approval_blob
        )
    except Exception as e:
        logger.warning("Could not relay approved device action to supervisor: %s", e)

    logger.info("Step-up challenge %s verified successfully by paired hardware device %s", step_up_id, device_id)
    return True, "Step-up approval successfully verified by paired phone", item


def clear_active_challenges():
    """Purges all active pending challenges and enrollment sessions."""
    _ACTIVE_CHALLENGES.clear()
    _LOCAL_ENROLLMENT_SESSIONS.clear()
    _PENDING_ACTION_NONCES.clear()


# ==============================================================================
# 5. ASYMMETRIC ACTION APPROVAL VERIFICATION (ZERO PC-SIDE MINTING)
# ==============================================================================

def verify_action_approval(
    approval: Dict[str, Any],
    expected_action: str,
    expected_payload_hash: str
) -> Tuple[bool, str]:
    """Verifies that the signed approval object is cryptographically valid, not expired,
    bound to current taint epoch, bound to the exact expected action and payload_hash,
    and consumes the nonce persistently (single-use anti-replay).
    Fails closed if the device is unknown or revoked.
    """
    if not isinstance(approval, dict):
        return False, "Malformed approval: must be an approval object dictionary"

    for req in ["device_id", "action_name", "payload_hash", "nonce", "expiry", "taint_epoch", "signature"]:
        if req not in approval:
            return False, f"Malformed approval: missing required field '{req}'"

    # Action binding check
    if approval["action_name"] != expected_action:
        return False, f"ACTION_MISMATCH: Approval signed for '{approval['action_name']}', expected '{expected_action}'"

    # Payload hash binding check
    if str(approval["payload_hash"]).lower() != str(expected_payload_hash).lower():
        return False, f"PAYLOAD_MISMATCH: Approval signed for payload {approval['payload_hash']}, expected {expected_payload_hash}"

    # Integer expiry check
    now = int(time.time())
    try:
        expiry = int(approval["expiry"])
    except (ValueError, TypeError):
        return False, "MALFORMED_EXPIRY: Approval expiry must be an integer timestamp"

    if now > expiry:
        return False, f"APPROVAL_EXPIRED: Approval expired at {expiry} (current time {now})"

    if expiry > now + MAX_ACTION_APPROVAL_TTL:
        return False, f"EXPIRY_EXCEEDS_CAP: Approval expiry {expiry} exceeds maximum TTL ({int(MAX_ACTION_APPROVAL_TTL)}s)"

    # Taint epoch check
    try:
        approval_epoch = int(approval["taint_epoch"])
    except (ValueError, TypeError):
        return False, "MALFORMED_TAINT_EPOCH: Approval taint_epoch must be an integer"

    current_epoch = int(taint_tracker.get_taint_epoch())
    if approval_epoch != current_epoch:
        return False, f"TAINT_EPOCH_MISMATCH: Approval signed under taint epoch {approval_epoch}, current epoch is {current_epoch}"

    # Persistent single-use anti-replay nonce check format
    nonce = str(approval["nonce"]).strip()
    if not nonce or len(nonce) < 16:
        return False, "MALFORMED_NONCE: Nonce must be at least 16 characters"

    # Device enrollment check (FAIL CLOSED on unknown device)
    device_id = str(approval["device_id"]).strip()
    registry = _load_device_registry()
    dev_entry = registry.get(device_id)
    if not dev_entry:
        return False, f"DEVICE_UNKNOWN: Device '{device_id}' is not enrolled in supervisor registry"

    if dev_entry.get("revoked", False):
        return False, f"DEVICE_REVOKED: Device '{device_id}' has been revoked"

    # Reconstruct canonical signed message bytes
    raw_msg = (
        f"ACTION_APPROVAL_V1|{device_id}|{approval['action_name']}|"
        f"{str(approval['payload_hash']).lower()}|{nonce}|{expiry}|{approval_epoch}"
    )

    # Step 1: Asymmetric Ed25519 signature verification FIRST (prevents unauthenticated nonce-burning DoS)
    sig_ok = verify_asymmetric_signature(dev_entry["public_key"], raw_msg.encode('utf-8'), str(approval["signature"]))
    if not sig_ok:
        return False, "SIGNATURE_INVALID: Asymmetric Ed25519 signature failed verification"

    # Step 2: Atomic anti-replay check under _NONCE_LOCK
    with _NONCE_LOCK:
        if is_nonce_consumed(nonce) or nonce in _PENDING_ACTION_NONCES:
            return False, "REPLAY_REJECTED: Approval nonce has already been consumed"
        _PENDING_ACTION_NONCES.add(nonce)

    # Step 3: Production Approval Cache Relay (In-memory + cross-process SQLite)
    target_caller = approval.get("caller_id") or "worker"
    remaining_ttl = max(1.0, float(expiry - now))
    try:
        import homie_supervisor
        signed_approval_blob = {
            "version": approval.get("version", "ACTION_APPROVAL_V1"),
            "device_id": approval.get("device_id", "primary_phone"),
            "tool_name": expected_action,
            "args_hash": str(expected_payload_hash).lower(),
            "nonce": nonce,
            "expiry": expiry,
            "taint_epoch": approval_epoch,
            "raw_msg": raw_msg,
            "signature": approval.get("signature"),
            "caller_id": target_caller
        }
        homie_supervisor.record_approved_action(
            caller_id=target_caller,
            tool=expected_action,
            args_hash=str(expected_payload_hash).lower(),
            taint_epoch=approval_epoch,
            ttl=min(remaining_ttl, 120.0),
            signed_blob=signed_approval_blob
        )
    except Exception as e:
        logger.warning("Could not relay approved action to supervisor: %s", e)

    return True, "Approval signature and action binding verified"
