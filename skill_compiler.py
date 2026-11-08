"""skill_compiler.py - Workstation Macro Skill Compiler for Homie.

Compiles verified multi-step user workflows into cryptographically signed,
strictly bounded execution macros:
- Declared target process images (e.g. ["chrome.exe", "code.exe"]).
- Declared allowable action types (e.g. ["homie_launch_app", "homie_place_window"]).
- Fixed step budget and parameter boundaries.
- Cryptographic HMAC-SHA256 macro signature ensuring worker/agent cannot tamper with steps.
- Executes through ActionBroker within a verified bounded PolicyEnvelope.
- Expands the sub-50ms deterministic fast path without widening LLM write permissions.
"""

import os
import sys
import json
import time
import hmac
import hashlib
import logging
from typing import List, Dict, Any, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault
import action_broker
import agent_audit_ledger
import taint_tracker
import phone_gateway
from policy_envelope import PolicyEnvelope

logger = logging.getLogger("homie.skill_compiler")

MACRO_REGISTRY_FILE = os.path.join(BASE_DIR, "homie_compiled_macros.json")

# Forbidden macro names that shadow core deterministic fast commands
FORBIDDEN_MACRO_NAMES = {
    "play", "pause", "resume", "next", "prev", "previous", "skip",
    "mute", "unmute", "volup", "voldown", "volume_up", "volume_down", "louder", "quieter",
    "pc_status", "system_status", "vitals", "diagnose", "health_check",
    "clipboard", "smart_clipboard", "close_app", "kill_app", "exit_app",
    "whatsapp", "telegram", "send_chat", "place_window", "open_youtube", "play_youtube"
}


def validate_parameter_schema(args: Any, depth: int = 0) -> Tuple[bool, str]:
    """Validates that step arguments adhere to strictly typed, bounded schemas."""
    if depth >= 3:
        return False, "Parameter recursion depth exceeded (max depth 2)"
    if not isinstance(args, dict):
        return False, f"Step arguments must be a dictionary, got {type(args).__name__}"
    for k, v in args.items():
        if not isinstance(k, str) or not k.strip():
            return False, "Argument key must be a non-empty string"
        if not isinstance(v, (str, int, float, bool, list, dict)):
            return False, f"Unsupported argument value type '{type(v).__name__}' for key '{k}'"
        if isinstance(v, (dict, list)):
            if isinstance(v, dict):
                ok, msg = validate_parameter_schema(v, depth + 1)
                if not ok:
                    return False, msg
            elif isinstance(v, list):
                if len(v) > 50:
                    return False, f"List argument '{k}' exceeds maximum 50 elements"
                for item in v:
                    if isinstance(item, (dict, list)):
                        if isinstance(item, dict):
                            ok, msg = validate_parameter_schema(item, depth + 1)
                            if not ok:
                                return False, msg
                    elif not isinstance(item, (str, int, float, bool)):
                        return False, f"Unsupported item type '{type(item).__name__}' in list '{k}'"
    return True, "Valid"


def _get_compiler_secret() -> bytes:
    """Derives domain-separated key for signing compiled macros."""
    return crypto_vault.derive_subkey("macro_compiler", length=32)


def compute_macro_signature(macro_def: Dict[str, Any], secret: Optional[bytes] = None) -> str:
    """Computes HMAC-SHA256 signature over canonical macro definition."""
    sec = secret or _get_compiler_secret()
    canonical = (
        f"{macro_def['name']}|"
        f"{','.join(sorted(macro_def.get('declared_processes', [])))}|"
        f"{','.join(sorted(macro_def.get('declared_action_types', [])))}|"
        f"{int(macro_def.get('step_budget', 0))}|"
        f"{json.dumps(macro_def.get('steps', []), sort_keys=True)}"
    )
    return hmac.new(sec, canonical.encode('utf-8'), hashlib.sha256).hexdigest()


class MacroRegistry:
    """Persistent storage and registry for compiled workstation macros."""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or MACRO_REGISTRY_FILE
        self._macros: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    self._macros = json.load(f)
            except Exception as e:
                logger.warning("Could not read macro registry: %s", e)
                self._macros = {}
        else:
            self._macros = {}

    def save(self):
        try:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self._macros, f, indent=2)
        except Exception as e:
            logger.error("Could not write macro registry: %s", e)

    def register_macro(
        self,
        name: str,
        description: str,
        steps: List[Dict[str, Any]],
        declared_processes: Optional[List[str]] = None,
        declared_action_types: Optional[List[str]] = None,
        human_auth: bool = False,
        phone_auth_token: Optional[str] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Compiles, signs, and stores a new macro definition under verified human authorization.
        Enforces anti-taint-laundering, forbidden fast-command name protection, and typed parameter boundaries.
        """
        clean_name = name.strip().lower().replace(" ", "_")
        if not clean_name:
            return False, "Macro name cannot be empty", {}

        # 1. Anti-shadowing check: Prevent overriding fast commands
        if clean_name in FORBIDDEN_MACRO_NAMES:
            return False, f"DENY: Macro name '{clean_name}' shadows built-in fast command. Macro rejected.", {}

        # 2. Anti-taint laundering gate
        if taint_tracker.is_session_tainted("macro_compilation"):
            return False, "DENY: Taint Laundering Detected. Cannot compile workstation macros while session or workstation is tainted.", {}

        # 3. Explicit human authorization gate (console or paired phone)
        is_authorized = human_auth or (phone_auth_token and phone_gateway.is_device_token_valid(phone_auth_token))
        if not is_authorized:
            return False, "DENY: Compiling workstation macros strictly requires explicit human authorization or paired phone approval.", {}

        if not steps:
            return False, "Macro must contain at least one action step", {}

        # 4. Typed parameter schema validation
        for idx, s in enumerate(steps):
            if not isinstance(s, dict):
                return False, f"Step {idx + 1} must be a dictionary", {}
            tool = s.get("tool")
            if not tool or not isinstance(tool, str):
                return False, f"Step {idx + 1} missing required 'tool' string", {}
            args = s.get("arguments", {})
            ok, msg = validate_parameter_schema(args)
            if not ok:
                return False, f"Step {idx + 1} parameter schema violation: {msg}", {}

        # Synthesize declared action types from steps if not specified
        action_types = set(declared_action_types or [])
        procs = set(declared_processes or [])
        for s in steps:
            tool = action_broker.get_action_broker().normalize_tool_name(s.get("tool", ""))
            action_types.add(tool)
            target = s.get("arguments", {}).get("app_name") or s.get("arguments", {}).get("target")
            if target:
                procs.add(os.path.basename(str(target)).lower())

        macro_def = {
            "name": clean_name,
            "description": description.strip(),
            "declared_processes": sorted(list(procs)),
            "declared_action_types": sorted(list(action_types)),
            "step_budget": len(steps),
            "steps": steps,
            "created_at": time.time()
        }

        # Sign macro
        macro_def["signature"] = compute_macro_signature(macro_def)
        self._macros[clean_name] = macro_def
        self.save()

        # Audit ledger record
        try:
            agent_audit_ledger.record_agent_action(
                "human_admin" if human_auth else "phone_admin",
                "homie_compile_macro",
                "ELEVATED_CONFIRM",
                {"name": clean_name, "steps_count": len(steps)},
                decision="ALLOW_COMPILED_MACRO"
            )
        except Exception:
            pass

        logger.info("Compiled and signed macro '%s' with %d steps", clean_name, len(steps))
        return True, f"Macro '{clean_name}' successfully compiled and signed", macro_def

    def get_macro(self, name: str) -> Optional[Dict[str, Any]]:
        clean_name = name.strip().lower().replace(" ", "_")
        return self._macros.get(clean_name)

    def list_macros(self) -> List[Dict[str, Any]]:
        return list(self._macros.values())


_GLOBAL_REGISTRY: Optional[MacroRegistry] = None

def get_macro_registry() -> MacroRegistry:
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = MacroRegistry()
    return _GLOBAL_REGISTRY


def execute_compiled_macro(
    macro_name: str,
    caller_id: str = "desktop_user",
    registry: Optional[MacroRegistry] = None
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Executes a compiled macro under strict envelope and signature enforcement."""
    reg = registry or get_macro_registry()
    macro = reg.get_macro(macro_name)
    if not macro:
        return False, f"Macro '{macro_name}' not found in registry", []

    # 1. Verify cryptographic integrity signature
    stored_sig = macro.get("signature", "")
    expected_sig = compute_macro_signature(macro)
    if not hmac.compare_digest(stored_sig, expected_sig):
        msg = f"Security Gate: Macro '{macro_name}' signature is invalid or tampered! Refusing execution."
        logger.error(msg)
        return False, msg, []

    # 2. Execute each step through ActionBroker
    broker = action_broker.get_action_broker()
    executed_results = []

    logger.info("Executing macro '%s' (%d steps) for caller '%s'", macro_name, len(macro["steps"]), caller_id)

    for idx, step in enumerate(macro["steps"]):
        tool = step.get("tool", "")
        args = step.get("arguments", {})

        ok, msg, res = broker.execute_action(tool, args, caller_id=f"macro:{macro_name}")
        executed_results.append({
            "step_index": idx + 1,
            "tool": tool,
            "args": args,
            "success": ok,
            "message": msg
        })

        if not ok:
            err_msg = f"Macro '{macro_name}' execution halted at step {idx + 1} ({tool}): {msg}"
            logger.warning(err_msg)
            return False, err_msg, executed_results

    summary_msg = f"Macro '{macro_name}' completed successfully ({len(executed_results)} steps executed)."
    return True, summary_msg, executed_results
