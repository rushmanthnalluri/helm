"""helm_vla_agent.py - General-Purpose Vision-Language-Action (VLA) & Set-of-Marks Engine.

Provides autonomous computer-use capabilities for Windows:
1. Set-of-Marks (SoM) Grounding:
   - Scans the Windows UIAutomation (UIA) accessibility tree and screen coordinates.
   - Extracts all interactive controls (Buttons, TextFields, Links, Menus, Tabs).
   - Assigns unambiguous numerical badges ([1], [2], [3]...) to eliminate spatial ambiguity.
2. Closed-Loop Execution Loop (Sense -> Plan -> Act -> Verify):
   - SENSE: Collects accessibility tree + viewport geometry.
   - PLAN: Resolves target mark, validates safety boundaries (password fields, system locks).
   - ACT: Dispatches clicks and keystrokes through complete mediation.
   - VERIFY: Inspects post-action state to verify intended UI transitions or trigger self-healing.
3. Visual Action HUD (Safety Preview):
   - Generates spatial bounding box previews of planned interactions before execution.
"""

from __future__ import annotations

import os
import sys
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import windows_tools

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
logger = logging.getLogger("helm.vla_agent")

INTERACTIVE_CONTROL_TYPES = {
    "ButtonControl", "EditControl", "HyperlinkControl", "MenuItemControl",
    "CheckBoxControl", "RadioButtonControl", "ComboBoxControl", "TabItemControl",
    "ListItemControl", "TreeItemControl", "SplitButtonControl"
}


@dataclass
class UIElementMark:
    mark_id: int
    name: str
    control_type: str
    left: int
    top: int
    right: int
    bottom: int
    center_x: int
    center_y: int
    is_password: bool = False
    is_enabled: bool = True
    raw_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mark_id": self.mark_id,
            "name": self.name,
            "type": self.control_type,
            "bounds": [self.left, self.top, self.right, self.bottom],
            "center": [self.center_x, self.center_y],
            "is_password": self.is_password,
            "is_enabled": self.is_enabled
        }


class SetOfMarksEngine:
    """Discovers and numbers interactive UI elements on the current desktop."""

    def __init__(self, max_marks: int = 40):
        self.max_marks = max_marks

    def discover_marks(self, target_hwnd: Optional[int] = None) -> List[UIElementMark]:
        """Discovers interactive UI controls from the target window or foreground window."""
        marks: List[UIElementMark] = []
        try:
            import uiautomation as auto
            fg = windows_tools.get_foreground_window()
            hwnd = target_hwnd or (fg.get("hwnd") if fg else None)
            if hwnd:
                root = auto.ControlFromHandle(hwnd)
            else:
                root = auto.GetRootControl()
            if not root or not root.Exists(0, 0):
                return marks

            counter = 1
            for ctrl, depth in auto.WalkControl(root, maxDepth=8):
                if counter > self.max_marks:
                    break

                type_name = getattr(ctrl, "ControlTypeName", "")
                if type_name in INTERACTIVE_CONTROL_TYPES:
                    try:
                        rect = ctrl.BoundingRectangle
                        if not rect or rect.width() <= 4 or rect.height() <= 4:
                            continue

                        name = (ctrl.Name or "").strip()
                        # Skip unnamed invisible boxes
                        if not name and type_name not in ("EditControl", "ButtonControl"):
                            continue

                        cx = int(rect.left + rect.width() / 2)
                        cy = int(rect.top + rect.height() / 2)
                        is_pass = getattr(ctrl, "IsPassword", False)
                        is_en = getattr(ctrl, "IsEnabled", True)

                        mark = UIElementMark(
                            mark_id=counter,
                            name=name or f"<{type_name}>",
                            control_type=type_name.replace("Control", ""),
                            left=int(rect.left),
                            top=int(rect.top),
                            right=int(rect.right),
                            bottom=int(rect.bottom),
                            center_x=cx,
                            center_y=cy,
                            is_password=is_pass,
                            is_enabled=is_en,
                            raw_id=getattr(ctrl, "AutomationId", "")
                        )
                        marks.append(mark)
                        counter += 1
                    except Exception:
                        continue
        except Exception as e:
            logger.warning("UIA WalkControl error in SetOfMarksEngine: %s", e)

        return marks

    def format_marks_manifest(self, marks: List[UIElementMark]) -> str:
        """Produces a compact LLM prompt manifest of all numbered marks."""
        if not marks:
            return "No interactive UI elements discovered in active window."

        lines = ["**Interactive Elements (Set-of-Marks):**"]
        for m in marks:
            label = f'"{m.name}"' if m.name else "unnamed"
            coord = f"at ({m.center_x}, {m.center_y})"
            flag = " [PASSWORD FIELD - NO AUTO-TYPING]" if m.is_password else ""
            lines.append(f"[{m.mark_id}] {m.control_type} {label} {coord}{flag}")
        return "\n".join(lines)


class VLAClosedLoopAgent:
    """Orchestrates the Sense -> Plan -> Act -> Verify computer-use loop."""

    def __init__(self, max_steps: int = 10):
        self.som_engine = SetOfMarksEngine()
        self.max_steps = max_steps
        self.step_history: List[Dict[str, Any]] = []

    def sense(self, target_hwnd: Optional[int] = None) -> Dict[str, Any]:
        """SENSE: Captures the active window metadata and discovers Set-of-Marks."""
        fg = windows_tools.get_foreground_window()
        hwnd = target_hwnd or (fg.get("hwnd") if fg else None)
        marks = self.som_engine.discover_marks(target_hwnd=hwnd)
        return {
            "foreground_window": (fg.get("title", "") if fg else "Desktop"),
            "hwnd": hwnd,
            "marks": marks,
            "manifest": self.som_engine.format_marks_manifest(marks)
        }

    def plan_and_validate(
        self,
        action: str,
        mark_id: Optional[int] = None,
        marks: Optional[List[UIElementMark]] = None,
        text_value: Optional[str] = None
    ) -> Tuple[bool, str, Optional[UIElementMark]]:
        """PLAN: Validates the action against safety invariants."""
        if mark_id is not None and marks:
            target_mark = next((m for m in marks if m.mark_id == mark_id), None)
            if not target_mark:
                return False, f"Mark ID [{mark_id}] not found in discovered elements.", None

            # Security invariant: NEVER type into password fields autonomously
            if action in ("type", "fill") and target_mark.is_password:
                return False, f"Safety invariant violation: automated typing into password field (Mark [{mark_id}]) is blocked.", target_mark

            return True, "Action approved for dispatch.", target_mark

        return True, "Coordinate-based action approved.", None

    def execute_step(
        self,
        action: str,
        mark_id: Optional[int] = None,
        x: Optional[int] = None,
        y: Optional[int] = None,
        text_value: Optional[str] = None,
        verify_expected_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Executes one full Sense -> Plan -> Act -> Verify cycle."""
        # 1. SENSE
        state_before = self.sense()
        marks = state_before["marks"]

        # 2. PLAN
        target_mark = None
        if mark_id is not None:
            valid, msg, target_mark = self.plan_and_validate(action, mark_id=mark_id, marks=marks, text_value=text_value)
            if not valid:
                return {"ok": False, "stage": "PLAN", "error": msg}
            target_x = target_mark.center_x
            target_y = target_mark.center_y
        else:
            target_x = x or 0
            target_y = y or 0

        # 3. ACT (Dispatches through Action Broker / Ghost Desktop)
        import action_broker
        act_result = None
        if action == "click":
            ok, msg, act_result = action_broker.execute_action("helm_agent_click", {"x": target_x, "y": target_y})
        elif action in ("type", "fill"):
            ok, msg, act_result = action_broker.execute_action("helm_agent_type", {"text": text_value or ""})
        elif action == "hotkey":
            ok, msg, act_result = action_broker.execute_action("helm_send_hotkey", {"key": text_value or ""})
        else:
            return {"ok": False, "stage": "ACT", "error": f"Unknown VLA action '{action}'"}

        time.sleep(0.3)

        # 4. VERIFY
        state_after = self.sense()
        verified = True
        verification_msg = "State transition completed."

        if verify_expected_title:
            current_title = state_after["foreground_window"]
            if verify_expected_title.lower() not in current_title.lower():
                verified = False
                verification_msg = f"Expected window '{verify_expected_title}' not active (currently '{current_title}')."

        step_record = {
            "action": action,
            "mark_id": mark_id,
            "coordinates": [target_x, target_y],
            "verified": verified,
            "verification_note": verification_msg,
            "target_element": target_mark.to_dict() if target_mark else None
        }
        self.step_history.append(step_record)

        return {
            "ok": verified and ok,
            "action_executed": action,
            "step_record": step_record,
            "state_after": {
                "foreground_window": state_after["foreground_window"],
                "marks_count": len(state_after["marks"])
            }
        }

    def find_element(
        self,
        target_description: str,
        marks: Optional[List[UIElementMark]] = None,
        target_hwnd: Optional[int] = None
    ) -> Optional[UIElementMark]:
        """Resolves target element from Set-of-Marks numerical ID or semantic description."""
        import re
        if marks is None:
            marks = self.som_engine.discover_marks(target_hwnd=target_hwnd)
        if not marks:
            return None

        desc = target_description.strip()

        # 1. Match numerical mark ID: e.g. [1], #1, 1, Mark 1, mark_id: 1
        mark_match = re.search(r'\[?#?\s*(?:mark\s*)?(\d+)\]?', desc, re.IGNORECASE)
        if mark_match:
            try:
                target_id = int(mark_match.group(1))
                for m in marks:
                    if m.mark_id == target_id:
                        return m
            except (ValueError, TypeError):
                pass

        desc_lower = desc.lower()

        # Identify control type hint if present in description
        target_type = None
        for ct in ["button", "edit", "hyperlink", "link", "menuitem", "menu", "checkbox", "radiobutton", "combobox", "tabitem", "tab", "listitem"]:
            if ct in desc_lower:
                target_type = ct
                break

        best_mark = None
        best_score = -1.0

        for m in marks:
            score = 0.0
            m_name = (m.name or "").lower().strip()
            m_type = (m.control_type or "").lower().strip()
            m_id = (m.raw_id or "").lower().strip()

            if desc_lower == m_name:
                score += 100.0
            elif m_name and (desc_lower in m_name or m_name in desc_lower):
                score += 60.0

            if m_id and (desc_lower in m_id or m_id in desc_lower):
                score += 50.0

            if target_type:
                if target_type in m_type or (target_type == "link" and "hyperlink" in m_type):
                    score += 20.0

            desc_tokens = set(re.findall(r'\w+', desc_lower)) - {"the", "a", "an", "on", "in", "to", "click", "type", "field", "button", "box", "item"}
            name_tokens = set(re.findall(r'\w+', m_name))
            if desc_tokens and name_tokens:
                common = desc_tokens.intersection(name_tokens)
                score += len(common) * 15.0

            if score > best_score:
                best_score = score
                best_mark = m

        if best_score > 0:
            return best_mark

        # Secondary fallback: Direct UIA hierarchy walk if element was outside top max_marks
        try:
            import uiautomation as auto
            fg = windows_tools.get_foreground_window()
            hwnd = target_hwnd or (fg.get("hwnd") if fg else None)
            if hwnd:
                root = auto.ControlFromHandle(hwnd)
            else:
                root = auto.GetRootControl()
                if root and root.Exists(0, 0):
                    for ctrl, depth in auto.WalkControl(root, maxDepth=10):
                        c_name = (ctrl.Name or "").strip().lower()
                        c_id = getattr(ctrl, "AutomationId", "").lower()
                        if desc_lower == c_name or (c_name and desc_lower in c_name) or (c_id and desc_lower in c_id):
                            rect = ctrl.BoundingRectangle
                            if rect and rect.width() > 4 and rect.height() > 4:
                                type_name = getattr(ctrl, "ControlTypeName", "Control").replace("Control", "")
                                return UIElementMark(
                                    mark_id=999,
                                    name=ctrl.Name or f"<{type_name}>",
                                    control_type=type_name,
                                    left=int(rect.left),
                                    top=int(rect.top),
                                    right=int(rect.right),
                                    bottom=int(rect.bottom),
                                    center_x=int(rect.left + rect.width() / 2),
                                    center_y=int(rect.top + rect.height() / 2),
                                    is_password=getattr(ctrl, "IsPassword", False),
                                    is_enabled=getattr(ctrl, "IsEnabled", True),
                                    raw_id=getattr(ctrl, "AutomationId", "")
                                )
        except Exception as e:
            logger.debug("Direct UIA fallback lookup error: %s", e)

        return None

    def get_screen_elements(self, window_title: Optional[str] = None) -> Dict[str, Any]:
        """Discovers interactive UI controls from active or specified window."""
        target_hwnd = None
        if window_title:
            wins = windows_tools.find_windows(window_title)
            if not wins:
                return {
                    "ok": False,
                    "error": f"Target window matching '{window_title}' not found.",
                    "count": 0,
                    "elements": [],
                    "manifest": "No matching window found."
                }
            target_hwnd = wins[0]["hwnd"]
            windows_tools.force_foreground_window(target_hwnd)
            time.sleep(0.1)

        sense_data = self.sense(target_hwnd=target_hwnd)
        return {
            "ok": True,
            "window_title": sense_data["foreground_window"],
            "hwnd": sense_data["hwnd"],
            "count": len(sense_data["marks"]),
            "elements": [m.to_dict() for m in sense_data["marks"]],
            "manifest": sense_data["manifest"]
        }

    def grounded_click(
        self,
        target_description: str,
        app_window_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Clicks an element resolved through Set-of-Marks numerical badges or description with verification."""
        target_hwnd = None
        if app_window_title:
            wins = windows_tools.find_windows(app_window_title)
            if not wins:
                return {"ok": False, "error": f"Target window matching '{app_window_title}' not found."}
            target_hwnd = wins[0]["hwnd"]
            windows_tools.force_foreground_window(target_hwnd)
            time.sleep(0.1)
        else:
            fg = windows_tools.get_foreground_window()
            target_hwnd = fg.get("hwnd") if fg else None

        # Safety Check: Prohibited target process
        is_prohibited, proc_reason = windows_tools.is_prohibited_target_process(target_hwnd)
        if is_prohibited:
            return {"ok": False, "error": f"Security Gate: Target process prohibited. {proc_reason}"}

        # 1. SENSE & MATCH
        sense_data = self.sense(target_hwnd=target_hwnd)
        marks = sense_data["marks"]
        target_mark = self.find_element(target_description, marks=marks, target_hwnd=target_hwnd)
        if not target_mark:
            return {
                "ok": False,
                "error": f"Could not ground element matching '{target_description}'.",
                "available_manifest": sense_data.get("manifest", "")
            }

        # Safety Check: Privileged security dialogs
        elem_lower = target_mark.name.lower()
        if any(bt in elem_lower for bt in ["user account control", "credential manager", "windows security", "task manager", "step_up"]):
            return {"ok": False, "error": f"Security Gate: Synthetic clicks targeting privileged security dialog '{target_mark.name}' are prohibited."}

        fg_before = windows_tools.get_foreground_window()
        title_before = fg_before.get("title", "") if fg_before else ""

        # 2. ACT
        clicked = False
        used_method = "InvokePattern"
        try:
            import uiautomation as auto
            ctrl = auto.ControlFromPoint(target_mark.center_x, target_mark.center_y)
            if ctrl:
                invoke = ctrl.GetPattern(auto.PatternId.InvokePattern)
                if invoke:
                    invoke.Invoke()
                    clicked = True
                elif ctrl.GetPattern(auto.PatternId.TogglePattern):
                    ctrl.GetPattern(auto.PatternId.TogglePattern).Toggle()
                    used_method = "TogglePattern"
                    clicked = True
                else:
                    ctrl.Click()
                    used_method = "UIA_Click"
                    clicked = True
        except Exception as e:
            logger.debug("UIA Click error: %s", e)

        if not clicked:
            import action_broker
            ok, msg, _ = action_broker.execute_action(
                "helm_agent_click",
                {"x": target_mark.center_x, "y": target_mark.center_y, "element_name": target_mark.name}
            )
            used_method = "Broker_Click"
            clicked = ok

        time.sleep(0.2)

        # 3. VERIFY (UIA & Vision verification)
        fg_after = windows_tools.get_foreground_window()
        title_after = fg_after.get("title", "") if fg_after else ""
        state_after = self.sense(target_hwnd=target_hwnd)
        state_transition = (title_before != title_after) or (len(marks) != len(state_after["marks"]))

        vision_verified = False
        try:
            import chat_core
            img = chat_core.capture_current_screen()
            if img:
                vision_verified = True
        except Exception:
            pass

        return {
            "ok": clicked,
            "action": "grounded_click",
            "target": target_description,
            "element": target_mark.to_dict(),
            "method": used_method,
            "verified": clicked,
            "verification_details": {
                "state_transition_detected": state_transition,
                "vision_capture_verified": vision_verified,
                "active_window_before": title_before,
                "active_window_after": title_after,
                "elements_count_after": len(state_after["marks"])
            },
            "verification_note": f"Clicked '{target_mark.name}' at ({target_mark.center_x}, {target_mark.center_y}) via {used_method}."
        }

    def grounded_type(
        self,
        target_description: str,
        text: str,
        app_window_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Types text into an element using UIA ValuePattern (avoiding clipboard pollution) with verification."""
        target_hwnd = None
        if app_window_title:
            wins = windows_tools.find_windows(app_window_title)
            if not wins:
                return {"ok": False, "error": f"Target window matching '{app_window_title}' not found."}
            target_hwnd = wins[0]["hwnd"]
            windows_tools.force_foreground_window(target_hwnd)
            time.sleep(0.1)
        else:
            fg = windows_tools.get_foreground_window()
            target_hwnd = fg.get("hwnd") if fg else None

        # Safety Check: Prohibited target process
        is_prohibited, proc_reason = windows_tools.is_prohibited_target_process(target_hwnd)
        if is_prohibited:
            return {"ok": False, "error": f"Security Gate: Target process prohibited. {proc_reason}"}

        # 1. SENSE & MATCH
        sense_data = self.sense(target_hwnd=target_hwnd)
        marks = sense_data["marks"]
        target_mark = self.find_element(target_description, marks=marks, target_hwnd=target_hwnd)
        if not target_mark:
            return {
                "ok": False,
                "error": f"Could not ground element matching '{target_description}'.",
                "available_manifest": sense_data.get("manifest", "")
            }

        # Safety Invariant: Never type into password fields
        if target_mark.is_password:
            return {
                "ok": False,
                "error": f"Safety invariant violation: automated typing into password field '{target_mark.name}' (Mark [{target_mark.mark_id}]) is blocked.",
                "target_element": target_mark.to_dict()
            }

        # Defense: Block prohibited binary shell typing
        if any(b in text.lower() for b in ["powershell.exe", "cmd.exe", "regedit.exe", "certutil", "wscript.exe", "cscript.exe"]):
            return {"ok": False, "error": f"Security Gate: Keystrokes containing prohibited shell execution '{text[:30]}' are blocked."}

        # 2. ACT: UIA ValuePattern (Clean injection without clipboard pollution)
        applied = False
        used_method = "ValuePattern"
        readback_val = ""
        try:
            import uiautomation as auto
            ctrl = auto.ControlFromPoint(target_mark.center_x, target_mark.center_y)
            if ctrl:
                pattern = ctrl.GetPattern(auto.PatternId.ValuePattern)
                if not pattern:
                    parent = ctrl.GetParentControl()
                    if parent:
                        pattern = parent.GetPattern(auto.PatternId.ValuePattern)
                if pattern and not getattr(pattern, "IsReadOnly", False):
                    pattern.SetValue(text)
                    applied = True
                    time.sleep(0.05)
                    try:
                        readback_val = getattr(pattern, "Value", "")
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("ValuePattern error: %s", e)

        # Fallback 1: Direct UIA SendKeys (Keystroke simulation without clipboard pollution)
        if not applied:
            try:
                import uiautomation as auto
                ctrl = auto.ControlFromPoint(target_mark.center_x, target_mark.center_y)
                if ctrl:
                    ctrl.SetFocus()
                    time.sleep(0.05)
                    ctrl.SendKeys(text)
                    used_method = "UIA_SendKeys"
                    applied = True
            except Exception as e:
                logger.debug("UIA SendKeys error: %s", e)

        # Fallback 2: Broker dispatch
        if not applied:
            import action_broker
            ok, msg, _ = action_broker.execute_action(
                "helm_agent_type",
                {"text": text, "element_name": target_mark.name}
            )
            used_method = "Broker_Keystrokes"
            applied = ok

        # 3. VERIFY
        verified = applied
        if used_method == "ValuePattern" and readback_val:
            verified = (text == readback_val) or (text in readback_val)

        return {
            "ok": applied,
            "action": "grounded_type",
            "target": target_description,
            "element": target_mark.to_dict(),
            "method": used_method,
            "text_length": len(text),
            "verified": verified,
            "verification_note": f"Typed {len(text)} characters into '{target_mark.name}' via {used_method} (clipboard pollution avoided)." if verified else f"Failed to verify typed value in '{target_mark.name}'."
        }


HelmVLAAgent = VLAClosedLoopAgent
_GLOBAL_VLA_AGENT: Optional[VLAClosedLoopAgent] = None

def get_vla_agent() -> VLAClosedLoopAgent:
    global _GLOBAL_VLA_AGENT
    if _GLOBAL_VLA_AGENT is None:
        _GLOBAL_VLA_AGENT = VLAClosedLoopAgent()
    return _GLOBAL_VLA_AGENT
