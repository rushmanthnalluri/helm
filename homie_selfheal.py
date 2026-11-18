"""homie_selfheal.py - Self-Healing Execution & Recovery Engine.

Automatically recovers from transient desktop automation and browser failures:
- Structured failure taxonomy (ELEMENT_NOT_FOUND, STALE_ELEMENT, TIMEOUT, POPUP_OR_DIALOG,
  NAVIGATION_ERROR, APP_NOT_RESPONDING, PERMISSION_DENIED, RATE_LIMIT).
- Automated remediation: Dismisses benign cookie/newsletter overlays, refocuses target windows,
  re-enumerates UIA nodes, waits for UI settle.
- Formal Idempotency Invariant: Side-effecting operations (sending messages, deleting files,
  purchasing, making payments, running shell code) are NEVER automatically retried.
"""

from __future__ import annotations

import re
import time
import logging
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("homie.selfheal")

# ---------------------------------------------------------------------------
# Failure Taxonomy
# ---------------------------------------------------------------------------

class FailureKind(str, Enum):
    ELEMENT_NOT_FOUND = "element_not_found"
    STALE_ELEMENT = "stale_element"
    TIMEOUT = "timeout"
    POPUP_OR_DIALOG = "popup_or_dialog"
    SIGN_IN_WALL = "sign_in_wall"
    CAPTCHA = "captcha"
    NAVIGATION_ERROR = "navigation_error"
    APP_NOT_RESPONDING = "app_not_responding"
    APP_CRASHED = "app_crashed"
    PERMISSION_DENIED = "permission_denied"
    FILE_LOCKED = "file_locked"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"


# High-risk side-effecting tools that must NEVER be retried
SIDE_EFFECT_TOOLS = frozenset({
    "homie_send_chat",
    "homie_safe_command",
    "homie_set_clipboard",
    "homie_close_app",
    "homie_kill_process",
    "homie_notarize_file",
    "send_email",
    "send_whatsapp",
    "delete_file",
    "execute_script"
})

# Refusals and security blocks must never be worked around
REFUSAL_PATTERN = re.compile(r"^(BLOCKED|REFUSED|Security Gate|Denied|The user DENIED)", re.I)

# Failure detection patterns (most specific first)
TAXONOMY_PATTERNS: list[tuple[FailureKind, re.Pattern[str]]] = [
    (FailureKind.CAPTCHA, re.compile(r"captcha|hcaptcha|cf-turnstile|turnstile|verify that you are human|are you a robot|unusual traffic", re.I)),
    (FailureKind.SIGN_IN_WALL, re.compile(r"sign[ -]?in to continue|please sign[ -]?in|log ?in required|session expired|401 unauthorized", re.I)),
    (FailureKind.STALE_ELEMENT, re.compile(r"stale element|no longer attached to dom|element is not attached|stale reference|ref is stale", re.I)),
    (FailureKind.POPUP_OR_DIALOG, re.compile(r"modal dialog|dialog is blocking|cookie banner|consent notice|overlay is blocking|intercepts pointer events", re.I)),
    (FailureKind.FILE_LOCKED, re.compile(r"sharing violation|used by another process|winerror 32|file is locked|resource busy", re.I)),
    (FailureKind.PERMISSION_DENIED, re.compile(r"permission denied|access is denied|winerror 5\b|operation not permitted|requires elevation", re.I)),
    (FailureKind.APP_CRASHED, re.compile(r"has crashed|target process terminated|browser disconnected|websocket closed|process exited", re.I)),
    (FailureKind.APP_NOT_RESPONDING, re.compile(r"not responding|application is busy|app is busy|did not open a window|window not found", re.I)),
    (FailureKind.NAVIGATION_ERROR, re.compile(r"net::err_|err_name_not_resolved|err_connection|connection refused|502 bad gateway|504 gateway timeout", re.I)),
    (FailureKind.TIMEOUT, re.compile(r"timed? out|timeout error|wait timed out|operation timed out", re.I)),
    (FailureKind.RATE_LIMIT, re.compile(r"rate limit|too many requests|429|quota exceeded", re.I)),
    (FailureKind.ELEMENT_NOT_FOUND, re.compile(r"nothing visible called|no visible control|element not found|no such element|could not locate", re.I)),
]

# Benign popup dismissal patterns (cookies, notifications, app banners)
BENIGN_BUTTON_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"^reject( all)?( cookies)?$",
        r"^decline( all)?$",
        r"^(use |allow )?(only )?(necessary|essential)( cookies)?( only)?$",
        r"^continue without accepting$",
        r"^not now$",
        r"^no,? thanks$",
        r"^maybe later$",
        r"^dismiss$",
        r"^close( banner| dialog)?$",
        r"^(x|×|✕)$",
        r"^got it$",
    )
]

# Danger keywords: buttons containing these must NEVER be clicked automatically
DANGER_KEYWORDS = re.compile(r"pay|card|checkout|buy|purchase|password|allow access|grant permission|delete|subscribe|install|admin", re.I)


def classify_failure(error_msg: str) -> FailureKind:
    """Classifies an error string into a structured FailureKind."""
    if not error_msg:
        return FailureKind.UNKNOWN

    clean = str(error_msg).strip()
    if REFUSAL_PATTERN.search(clean):
        return FailureKind.PERMISSION_DENIED

    for kind, pattern in TAXONOMY_PATTERNS:
        if pattern.search(clean):
            return kind

    return FailureKind.UNKNOWN


def is_retryable(tool_name: str, failure_kind: FailureKind) -> bool:
    """Determines whether a failed action is safe and meaningful to self-heal and retry."""
    # Strict Invariant 1: Side-effecting tools cannot be automatically retried
    clean_tool = tool_name.lower().replace("homie_", "")
    if clean_tool in SIDE_EFFECT_TOOLS or tool_name in SIDE_EFFECT_TOOLS:
        return False

    # Strict Invariant 2: Security refusals or auth walls cannot be bypassed
    if failure_kind in (FailureKind.PERMISSION_DENIED, FailureKind.SIGN_IN_WALL, FailureKind.CAPTCHA):
        return False

    # Retryable desktop/browser failures
    return failure_kind in (
        FailureKind.ELEMENT_NOT_FOUND,
        FailureKind.STALE_ELEMENT,
        FailureKind.POPUP_OR_DIALOG,
        FailureKind.TIMEOUT,
        FailureKind.APP_NOT_RESPONDING,
        FailureKind.RATE_LIMIT
    )


def attempt_recovery(
    tool_name: str,
    arguments: Dict[str, Any],
    failure_kind: FailureKind,
    error_msg: str
) -> Tuple[bool, str]:
    """Applies recovery actions based on failure classification.
    
    Returns:
        (recovery_applied: bool, explanation: str)
    """
    logger.info("Self-heal evaluating tool '%s' under failure '%s'", tool_name, failure_kind.value)

    if not is_retryable(tool_name, failure_kind):
        return False, f"Action '{tool_name}' ({failure_kind.value}) is not eligible for automatic retry."

    # Strategy 1: Pop-up / Cookie Dialog Interception
    if failure_kind == FailureKind.POPUP_OR_DIALOG:
        try:
            import windows_tools
            # Try to hit Escape or dismiss topmost dialog
            windows_tools.send_hotkey("esc")
            time.sleep(0.3)
            return True, "Dismissed blocking overlay/dialog via safe Escape event."
        except Exception as e:
            return False, f"Failed to dismiss overlay: {e}"

    # Strategy 2: App Not Responding or Window Inactive
    elif failure_kind in (FailureKind.APP_NOT_RESPONDING, FailureKind.STALE_ELEMENT, FailureKind.ELEMENT_NOT_FOUND):
        app_name = arguments.get("app_name") or arguments.get("target_process")
        if app_name:
            try:
                import windows_tools
                # Re-activate window
                windows = windows_tools.find_windows(app_name)
                if windows:
                    target_hwnd = windows[0].get("hwnd")
                    if target_hwnd:
                        import win32gui
                        win32gui.SetForegroundWindow(target_hwnd)
                        time.sleep(0.4)
                        return True, f"Re-focused target window '{app_name}' and allowed UI to settle."
            except Exception:
                pass

        time.sleep(0.5)
        return True, "Waited 500ms for UI tree to stabilize."

    # Strategy 3: Rate Limiting
    elif failure_kind == FailureKind.RATE_LIMIT:
        time.sleep(2.0)
        return True, "Applied 2-second rate-limit backoff."

    # Strategy 4: Timeout
    elif failure_kind == FailureKind.TIMEOUT:
        time.sleep(1.0)
        return True, "Waited 1.0s for slow I/O or background network response."

    return False, "No automated self-healing strategy available for this error."
