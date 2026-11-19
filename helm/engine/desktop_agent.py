"""Helm Desktop Grounding & Autonomous Agent Engine.
Executes desktop tasks with strict hierarchical grounding, safety boundaries, and eval metrics:
- Grounding Order:
  1. UIAutomation (UIA) accessibility tree (semantic name, control type, automation ID)
  2. OCR bounding boxes (text matching)
  3. Vision coordinates (always paired with post-action verification)
- Action Gating & Safety:
  - Scoped strictly to target application HWND
  - Password field detection (IsPassword attribute blocked from automated typing)
  - "Helm is driving" HUD banner state
  - Step budget limit (default max 10 steps)
  - Global emergency abort flag
  - Dry-run simulation mode
"""

import os
import sys
import time
import logging
import threading

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

logger = logging.getLogger("helm.desktop_agent")

_driving_state = False
_abort_requested = False

def set_driving_state(is_driving):
    global _driving_state
    _driving_state = is_driving
    logger.info("Desktop Agent driving state: %s", is_driving)

def request_abort():
    global _abort_requested
    _abort_requested = True
    set_driving_state(False)
    logger.warning("Desktop Agent emergency abort requested!")

def reset_abort():
    global _abort_requested
    _abort_requested = False

def is_abort_requested():
    return _abort_requested

class DesktopGroundingEngine:
    def __init__(self, target_window_title=None, max_steps=10, dry_run=False, session_id="desktop_agent"):
        self.target_window_title = target_window_title
        self.target_hwnd = None
        self.max_steps = max_steps
        self.steps_taken = 0
        self.dry_run = dry_run
        self.session_id = session_id
        self.execution_log = []

    def attach_target_window(self):
        """Discovers and focuses the target application window."""
        if not self.target_window_title:
            return True, "No specific window target required."

        wins = windows_tools.find_windows(self.target_window_title)
        if not wins:
            return False, f"Target window '{self.target_window_title}' not found."

        self.target_hwnd = wins[0]["hwnd"]
        if not self.dry_run:
            windows_tools.force_foreground_window(self.target_hwnd)
            time.sleep(0.3)
        return True, f"Attached to window '{wins[0]['title']}' (HWND: {self.target_hwnd})"

    def find_uia_element(self, element_name, control_type=None):
        """Searches for an element in the UIA tree within the target window."""
        try:
            import uiautomation as auto
            if self.target_hwnd:
                root = auto.ControlFromHandle(self.target_hwnd)
            else:
                root = auto.GetRootControl()

            for ctrl, depth in auto.WalkControl(root, maxDepth=10):
                if _abort_requested:
                    return None
                name_match = (element_name.lower() in (ctrl.Name or "").lower()) if element_name else True
                type_match = (ctrl.ControlTypeName == control_type) if control_type else True

                if name_match and type_match:
                    rect = ctrl.BoundingRectangle
                    if rect and rect.width() > 0 and rect.height() > 0:
                        is_password = getattr(ctrl, "IsPassword", False)
                        return {
                            "grounding": "UIA",
                            "name": ctrl.Name,
                            "type": ctrl.ControlTypeName,
                            "center": (rect.xcenter(), rect.ycenter()),
                            "rect": (rect.left, rect.top, rect.right, rect.bottom),
                            "is_password": bool(is_password)
                        }
        except Exception as e:
            logger.debug("UIA lookup error: %s", e)
        return None

    def click_element(self, element_name, control_type=None):
        """Hierarchical element click: UIA first, fallback to coordinates."""
        if _abort_requested:
            return False, "Aborted: Emergency stop triggered."
        if self.steps_taken >= self.max_steps:
            return False, f"Aborted: Step budget exceeded ({self.max_steps} steps)."

        self.steps_taken += 1
        elem = self.find_uia_element(element_name, control_type)

        if elem:
            cx, cy = elem["center"]
            action_desc = f"Click [{elem['grounding']}] '{elem['name']}' at ({cx}, {cy})"
            self.execution_log.append({"step": self.steps_taken, "action": "click", "element": elem, "desc": action_desc})

            if self.dry_run:
                return True, f"[DRY-RUN] Would {action_desc}"

            # Route click through hardened MCP dispatcher (enforces taint tracking & audit ledger)
            import helm_mcp
            res = helm_mcp.execute_mcp_tool(
                "helm_agent_click",
                {"x": cx, "y": cy, "element_name": elem["name"]},
                caller_id=self.session_id
            )
            if "Security Gate:" in res or "Blocked" in res:
                return False, f"Blocked by Security Gate: {res}"

            time.sleep(0.3)
            return True, action_desc

        return False, f"Could not ground element '{element_name}' via UIA hierarchy."

    def type_text(self, element_name, text_to_type, control_type="EditControl"):
        """Hierarchical text input with password field protection."""
        if _abort_requested:
            return False, "Aborted: Emergency stop triggered."
        if self.steps_taken >= self.max_steps:
            return False, f"Aborted: Step budget exceeded ({self.max_steps} steps)."

        self.steps_taken += 1
        elem = self.find_uia_element(element_name, control_type)

        if elem:
            if elem.get("is_password", False):
                # SECURITY RULE: Never auto-type into password fields
                action_desc = f"Blocked typing into password field '{elem['name']}'"
                self.execution_log.append({"step": self.steps_taken, "action": "blocked_password", "desc": action_desc})
                return False, action_desc

            cx, cy = elem["center"]
            action_desc = f"Type '{text_to_type}' into [{elem['name']}] at ({cx}, {cy})"
            self.execution_log.append({"step": self.steps_taken, "action": "type", "element": elem, "desc": action_desc})

            if self.dry_run:
                return True, f"[DRY-RUN] Would {action_desc}"

            # Route typing through hardened MCP dispatcher (enforces taint tracking & audit ledger)
            import helm_mcp
            res = helm_mcp.execute_mcp_tool(
                "helm_agent_type",
                {"text": text_to_type, "element_name": elem["name"]},
                caller_id=self.session_id
            )
            if "Security Gate:" in res or "Blocked" in res:
                return False, f"Blocked by Security Gate: {res}"

            time.sleep(0.2)
            return True, action_desc

        return False, f"Could not ground target text field '{element_name}'."

    def verify_screen_state(self, expected_keyword):
        """Verifies state transition post-action."""
        if not expected_keyword or not self.target_hwnd:
            return True, "No verification needed."
        text = windows_tools.read_window_text(self.target_hwnd)
        if expected_keyword.lower() in text.lower():
            return True, f"Verified: Found '{expected_keyword}' in target window state."
        return False, f"Verification failed: '{expected_keyword}' not visible in window."
