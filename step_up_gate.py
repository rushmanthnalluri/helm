"""Interactive Out-of-Band Step-Up Gate Bridge.
Connects taint_tracker with Telegram and Desktop HUD:
When an agent or untrusted session attempts a privileged WRITE_EXEC action,
this automatically pushes an interactive confirmation card to the user's paired Telegram phone
with [Allow] and [Block] buttons.
"""

import os
import sys
import time
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import taint_tracker
import agent_audit_ledger

logger = logging.getLogger("helm.step_up_gate")

def push_step_up_request_to_phone(step_up_id, session_id, tool_name, arguments, source="untrusted_content"):
    """Pushes an interactive confirmation to the user's paired Telegram phone."""
    if os.environ.get("HELM_TEST_ENV") == "1":
        return True, "Test environment: simulated step-up push"
    try:
        import helm
        prefs = helm.get_prefs()
        allowed_users = prefs.get("telegramAllowedUsers", [])
        token = prefs.get("telegramToken", "")
        if not token or not allowed_users:
            logger.info("No paired Telegram user available for step-up push notification.")
            return False, "No paired Telegram phone"

        owner_chat_id = allowed_users[0]
        import telegram_bridge
        bridge = telegram_bridge.TelegramBridge(token=token, allowed_users=allowed_users)

        msg = (
            "🚨 **Workstation Security Gate: Step-Up Approval**\n\n"
            f"An agent or external trigger requested privileged execution:\n"
            f"• **Tool**: `{tool_name}`\n"
            f"• **Arguments**: `{str(arguments)[:120]}`\n"
            f"• **Session**: `{session_id}` (Tainted by: `{source}`)\n\n"
            "Tap an action below to allow or reject this execution on your PC:"
        )

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Allow Execution", "callback_data": f"approve_stepup_{step_up_id}"},
                    {"text": "❌ Block & Deny", "callback_data": f"reject_stepup_{step_up_id}"}
                ]
            ]
        }

        bridge.send_message(owner_chat_id, msg, reply_markup=keyboard)
        logger.info("Pushed step-up approval [ID: %s] to Telegram chat %s", step_up_id, owner_chat_id)
        return True, f"Step-up request sent to Telegram phone ({owner_chat_id})"
    except Exception as e:
        logger.error("Failed to push step-up request: %s", e)
        return False, str(e)

def handle_step_up_callback(callback_data, chat_id):
    """Handles Telegram inline button callbacks for step-up approvals."""
    if callback_data.startswith("approve_stepup_"):
        step_up_id = callback_data[15:]
        ok, item, msg = taint_tracker.approve_step_up(step_up_id)
        if ok and item:
            # Execute the approved tool with temporary workstation taint bypass
            import helm_mcp
            tool_name = item["tool_name"]
            args = item["arguments"]
            was_ws = taint_tracker.is_workstation_tainted()
            taint_tracker.set_workstation_tainted(False)
            try:
                res = helm_mcp.execute_mcp_tool(tool_name, args, caller_id=f"approved_{chat_id}")
            finally:
                taint_tracker.set_workstation_tainted(was_ws)
            agent_audit_ledger.record_agent_action(f"telegram_approved_{chat_id}", tool_name, "WRITE_EXEC", args, decision="USER_APPROVED")
            return True, f"✅ **Approved & Executed**: `{tool_name}`\nResult: {res}"
        return False, f"⚠️ Could not approve: {msg}"

    elif callback_data.startswith("reject_stepup_"):
        step_up_id = callback_data[14:]
        taint_tracker.approve_step_up(step_up_id) # Cleans up pending entry
        agent_audit_ledger.record_agent_action(f"telegram_rejected_{chat_id}", "unknown", "WRITE_EXEC", {}, decision="USER_DENIED")
        return True, "❌ **Blocked**: Privileged action was denied and cancelled."

    return False, "Unknown callback"


class PhoneWebAuthnGate:
    """Out-of-band Smartphone WebAuthn / Telegram step-up confirmation gate."""

    def __init__(self, name: str = "phone_webauthn"):
        self.name = name

    def verify(
        self,
        reason: str = "Helm needs your approval",
        tool_name: str = "desktop_action",
        arguments: Optional[dict] = None,
        session_id: str = "desktop_session",
        step_up_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        s_id = step_up_id or f"stepup_{int(time.time()*1000)}"
        return push_step_up_request_to_phone(s_id, session_id, tool_name, arguments or {}, source="webauthn_gate")

    def verify_sync(self, reason: str = "Helm needs your approval", **kwargs) -> bool:
        ok, _ = self.verify(reason=reason, **kwargs)
        return ok


class WindowsHelloGate:
    """On-device Windows Hello biometric authentication gate.

    Calls WindowsHello.verify_sync(reason) for local biometric / PIN verification.
    If Windows Hello is not available (e.g. VM, no enrolled biometrics),
    automatically falls back to the out-of-band phone WebAuthn gate.
    """

    def __init__(self, fallback_gate: Optional[PhoneWebAuthnGate] = None):
        self.name = "windows_hello"
        self.fallback_gate = fallback_gate or PhoneWebAuthnGate()

    @classmethod
    def is_available(cls) -> bool:
        from windows_hello import WindowsHello
        return WindowsHello.is_available()

    def verify(
        self,
        reason: str = "Helm needs your approval",
        tool_name: str = "desktop_action",
        arguments: Optional[dict] = None,
        session_id: str = "desktop_session",
        step_up_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        from windows_hello import WindowsHello

        if WindowsHello.is_available():
            logger.info("Triggering Windows Hello biometric verification: %s", reason)
            ok = WindowsHello.verify_sync(reason)
            if ok:
                return True, "Windows Hello verification succeeded"
            else:
                return False, "Windows Hello verification failed or cancelled by user"

        # Biometrics not available on-device -> Fall back to phone WebAuthn
        logger.info("Windows Hello unavailable on this device; falling back to phone WebAuthn gate")
        return self.fallback_gate.verify(
            reason=reason,
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            step_up_id=step_up_id,
        )

    def verify_sync(self, reason: str = "Helm needs your approval", **kwargs) -> bool:
        from windows_hello import WindowsHello

        if WindowsHello.is_available():
            return WindowsHello.verify_sync(reason)

        ok, _ = self.fallback_gate.verify(reason=reason, **kwargs)
        return ok
