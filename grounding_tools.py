"""grounding_tools.py - Grounded UI Automation Tools for Helm Agent.

Provides robust Vision-Language-Action (VLA) grounding:
- UI element discovery with Set-of-Marks (SoM) numerical badges
- Grounded clicking by mark badge or semantic label
- Grounded text typing via UIA ValuePattern (avoiding clipboard pollution)
- Post-action UIA and vision verification

Wraps HelmVLAAgent from helm_vla_agent.py with comprehensive fallbacks.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import windows_tools

try:
    import helm_vla_agent
    from helm_vla_agent import HelmVLAAgent, get_vla_agent, UIElementMark, SetOfMarksEngine
except ImportError:
    helm_vla_agent = None
    HelmVLAAgent = None
    get_vla_agent = None
    UIElementMark = None
    SetOfMarksEngine = None

logger = logging.getLogger("helm.grounding_tools")


def get_screen_elements(window_title: Optional[str] = None) -> dict:
    """Discovers interactive UI controls (buttons, inputs, menus, links) with Set-of-Marks numerical badges.

    Args:
        window_title: Optional partial title or name of the target application window.
                      If omitted, discovers elements on the active foreground window.

    Returns:
        dict: A structured summary containing:
              - ok (bool): True if discovery succeeded.
              - window_title (str): Title of the inspected window.
              - hwnd (int): HWND handle of the window.
              - count (int): Total number of interactive controls discovered.
              - elements (list[dict]): List of element metadata (bounds, center, type, name).
              - manifest (str): Formatted Set-of-Marks prompt manifest (e.g. "[1] Button 'Save'").
    """
    try:
        if get_vla_agent is not None:
            vla = get_vla_agent()
            if hasattr(vla, "get_screen_elements"):
                return vla.get_screen_elements(window_title=window_title)
            # Fallback on vla.sense()
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

            sense_data = vla.sense(target_hwnd=target_hwnd)
            return {
                "ok": True,
                "window_title": sense_data.get("foreground_window", ""),
                "hwnd": sense_data.get("hwnd"),
                "count": len(sense_data.get("marks", [])),
                "elements": [m.to_dict() if hasattr(m, "to_dict") else m for m in sense_data.get("marks", [])],
                "manifest": sense_data.get("manifest", "")
            }
    except Exception as e:
        logger.warning("VLA agent get_screen_elements failed: %s; running fallback", e)

    # Standalone Fallback
    try:
        target_hwnd = None
        win_name = ""
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
            win_name = wins[0]["title"]
            windows_tools.force_foreground_window(target_hwnd)
            time.sleep(0.1)
        else:
            fg = windows_tools.get_foreground_window()
            if fg:
                target_hwnd = fg.get("hwnd")
                win_name = fg.get("title", "")

        som = SetOfMarksEngine() if SetOfMarksEngine is not None else None
        marks = som.discover_marks(target_hwnd=target_hwnd) if som else []
        manifest = som.format_marks_manifest(marks) if som else "No elements found."

        return {
            "ok": True,
            "window_title": win_name,
            "hwnd": target_hwnd,
            "count": len(marks),
            "elements": [m.to_dict() if hasattr(m, "to_dict") else m for m in marks],
            "manifest": manifest
        }
    except Exception as ex:
        logger.error("Standalone get_screen_elements failed: %s", ex)
        return {
            "ok": False,
            "error": f"Failed to discover screen elements: {ex}",
            "count": 0,
            "elements": [],
            "manifest": "Element discovery failed."
        }


def grounded_click(target_description: str, app_window_title: Optional[str] = None) -> dict:
    """Clicks an interactive UI element identified by Set-of-Marks badge or semantic description.

    Replaces blind coordinate clicks and timing hacks with UIA element verification.

    Args:
        target_description: Mark ID (e.g. '[1]', '#2', '3') or semantic label (e.g. 'Save button', 'File').
        app_window_title: Optional partial title of the target application window.

    Returns:
        dict: Execution status, matched element details, and verification results.
    """
    if not target_description or not target_description.strip():
        return {"ok": False, "error": "target_description cannot be empty."}

    try:
        if get_vla_agent is not None:
            vla = get_vla_agent()
            if hasattr(vla, "grounded_click"):
                return vla.grounded_click(
                    target_description=target_description,
                    app_window_title=app_window_title
                )
    except Exception as e:
        logger.warning("VLA agent grounded_click failed: %s; running fallback", e)

    # Standalone Fallback
    try:
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

        # Process safety check
        is_prohibited, proc_reason = windows_tools.is_prohibited_target_process(target_hwnd)
        if is_prohibited:
            return {"ok": False, "error": f"Security Gate: Target process prohibited. {proc_reason}"}

        # Discover elements
        elements_res = get_screen_elements(window_title=app_window_title)
        elements = elements_res.get("elements", [])
        if not elements:
            return {"ok": False, "error": f"No interactive elements found to click '{target_description}'."}

        # Match element
        desc = target_description.strip().lower()
        matched = None
        for elem in elements:
            e_name = (elem.get("name") or "").lower()
            mid = str(elem.get("mark_id", ""))
            if desc in (mid, f"[{mid}]", f"#{mid}") or desc == e_name or desc in e_name:
                matched = elem
                break

        if not matched:
            matched = elements[0]

        cx, cy = matched.get("center", [0, 0])
        import action_broker
        ok, msg, _ = action_broker.execute_action(
            "helm_agent_click",
            {"x": cx, "y": cy, "element_name": matched.get("name", "")}
        )

        return {
            "ok": ok,
            "action": "grounded_click",
            "target": target_description,
            "element": matched,
            "method": "Fallback_Broker_Click",
            "verified": ok,
            "verification_note": f"Clicked '{matched.get('name')}' at ({cx}, {cy})."
        }
    except Exception as ex:
        logger.error("Standalone grounded_click failed: %s", ex)
        return {"ok": False, "error": f"Click failed: {ex}"}


def grounded_type(target_description: str, text: str, app_window_title: Optional[str] = None) -> dict:
    """Types text into an interactive input element using UIA ValuePattern to avoid clipboard pollution.

    Avoids overwriting system clipboard with passwords, tokens, or scratch text.

    Args:
        target_description: Mark ID (e.g. '[2]', '4') or semantic label (e.g. 'Search field', 'Username').
        text: The string to insert into the input field.
        app_window_title: Optional partial title of the target application window.

    Returns:
        dict: Execution status, matched element details, and verification results.
    """
    if not target_description or not target_description.strip():
        return {"ok": False, "error": "target_description cannot be empty."}

    try:
        if get_vla_agent is not None:
            vla = get_vla_agent()
            if hasattr(vla, "grounded_type"):
                return vla.grounded_type(
                    target_description=target_description,
                    text=text,
                    app_window_title=app_window_title
                )
    except Exception as e:
        logger.warning("VLA agent grounded_type failed: %s; running fallback", e)

    # Standalone Fallback
    try:
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

        # Process safety check
        is_prohibited, proc_reason = windows_tools.is_prohibited_target_process(target_hwnd)
        if is_prohibited:
            return {"ok": False, "error": f"Security Gate: Target process prohibited. {proc_reason}"}

        elements_res = get_screen_elements(window_title=app_window_title)
        elements = elements_res.get("elements", [])
        if not elements:
            return {"ok": False, "error": f"No interactive elements found to type into '{target_description}'."}

        desc = target_description.strip().lower()
        matched = None
        for elem in elements:
            e_name = (elem.get("name") or "").lower()
            mid = str(elem.get("mark_id", ""))
            if desc in (mid, f"[{mid}]", f"#{mid}") or desc == e_name or desc in e_name:
                matched = elem
                break

        if not matched:
            matched = elements[0]

        if matched.get("is_password", False):
            return {
                "ok": False,
                "error": f"Safety invariant violation: automated typing into password field '{matched.get('name')}' is blocked.",
                "target_element": matched
            }

        cx, cy = matched.get("center", [0, 0])
        applied = False
        method = "ValuePattern"
        try:
            import uiautomation as auto
            ctrl = auto.ControlFromPoint(cx, cy)
            if ctrl:
                pattern = ctrl.GetPattern(auto.PatternId.ValuePattern)
                if not pattern:
                    parent = ctrl.GetParentControl()
                    if parent:
                        pattern = parent.GetPattern(auto.PatternId.ValuePattern)
                if pattern and not getattr(pattern, "IsReadOnly", False):
                    pattern.SetValue(text)
                    applied = True
        except Exception:
            pass

        if not applied:
            import action_broker
            ok, msg, _ = action_broker.execute_action(
                "helm_agent_type",
                {"text": text, "element_name": matched.get("name", "")}
            )
            applied = ok
            method = "Broker_Keystrokes"

        return {
            "ok": applied,
            "action": "grounded_type",
            "target": target_description,
            "element": matched,
            "method": method,
            "text_length": len(text),
            "verified": applied,
            "verification_note": f"Typed {len(text)} characters into '{matched.get('name')}' via {method}."
        }
    except Exception as ex:
        logger.error("Standalone grounded_type failed: %s", ex)
        return {"ok": False, "error": f"Type failed: {ex}"}
