"""helm_layout_profiles.py - Smart Window Layout Profiles for Helm.

Captures, saves, and restores multi-monitor window arrangements:
- Snapshots visible windows (rect, monitor, process name, window title)
- Stores named layout profiles in ~/.config/helm/layout_profiles.json
- Deterministically repositions and resizes windows on demand (SetWindowPos)
- Supports profile listing, inspection, restoration, and deletion
- Thread-safe and atomic persistence
"""

import os
import sys
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

logger = logging.getLogger("helm.layout_profiles")

_LOCK = threading.RLock()


def get_layout_profiles_path() -> Path:
    """Returns persistent path to layout_profiles.json."""
    custom = os.environ.get("HELM_LAYOUT_PROFILES_PATH")
    if custom:
        return Path(custom).resolve()
    base = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
    return (base / "layout_profiles.json").resolve()


def _load_profiles_data() -> Dict[str, Any]:
    path = get_layout_profiles_path()
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return {}
        data = json.loads(content)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.warning("Could not read layout profiles from %s: %s", path, e)
        return {}


def _save_profiles_data(data: Dict[str, Any]) -> bool:
    path = get_layout_profiles_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp_path, path)
        return True
    except Exception as e:
        logger.error("Failed to write layout profiles to %s: %s", path, e)
        return False


def capture_current_layout() -> Dict[str, Any]:
    """Captures all visible application windows and their current coordinates."""
    monitors = windows_tools.get_monitors()
    all_windows = windows_tools.find_windows()
    
    captured_windows = []
    for w in all_windows:
        hwnd = w.get("hwnd")
        proc_name = (w.get("proc_name") or "").strip()
        title = (w.get("title") or "").strip()
        rect = w.get("rect")
        
        # Skip empty, tiny, or system desktop windows
        if not proc_name or not rect:
            continue
        left, top, right, bottom = rect
        width = right - left
        height = bottom - top
        if width <= 100 or height <= 100:
            continue
        if proc_name.lower() in ("explorer.exe", "shellexperiencehost.exe", "searchhost.exe") and not title:
            continue

        captured_windows.append({
            "proc_name": proc_name,
            "title": title[:100],
            "rect": {
                "left": left,
                "top": top,
                "right": right,
                "bottom": bottom,
                "width": width,
                "height": height
            }
        })

    return {
        "timestamp": os.path.getmtime(get_layout_profiles_path()) if get_layout_profiles_path().exists() else None,
        "monitors": monitors,
        "windows": captured_windows
    }


def save_profile(name: str, description: str = "") -> Tuple[bool, str]:
    """Saves the current desktop window layout under a named profile."""
    clean_name = str(name).strip().lower()
    if not clean_name:
        return False, "Profile name cannot be empty."

    layout = capture_current_layout()
    if not layout.get("windows"):
        return False, "No active application windows found to capture."

    with _LOCK:
        profiles = _load_profiles_data()
        profiles[clean_name] = {
            "name": clean_name,
            "description": description or f"Layout captured with {len(layout['windows'])} windows",
            "window_count": len(layout["windows"]),
            "windows": layout["windows"],
            "monitors": layout.get("monitors", [])
        }
        ok = _save_profiles_data(profiles)
        if ok:
            return True, f"Saved layout profile '{clean_name}' with {len(layout['windows'])} window(s)."
        return False, f"Failed to persist layout profile '{clean_name}'."


def list_profiles() -> List[Dict[str, Any]]:
    """Returns a list of all saved window layout profiles."""
    with _LOCK:
        profiles = _load_profiles_data()
        result = []
        for name, data in profiles.items():
            result.append({
                "name": name,
                "description": data.get("description", ""),
                "window_count": data.get("window_count", len(data.get("windows", []))),
                "monitors_count": len(data.get("monitors", []))
            })
        return sorted(result, key=lambda x: x["name"])


def get_profile(name: str) -> Optional[Dict[str, Any]]:
    """Retrieves layout details for a specific profile name."""
    clean_name = str(name).strip().lower()
    with _LOCK:
        profiles = _load_profiles_data()
        return profiles.get(clean_name)


def delete_profile(name: str) -> Tuple[bool, str]:
    """Deletes a saved window layout profile."""
    clean_name = str(name).strip().lower()
    with _LOCK:
        profiles = _load_profiles_data()
        if clean_name not in profiles:
            return False, f"Profile '{clean_name}' does not exist."
        del profiles[clean_name]
        ok = _save_profiles_data(profiles)
        if ok:
            return True, f"Deleted layout profile '{clean_name}'."
        return False, f"Failed to delete layout profile '{clean_name}'."


def apply_profile(name: str) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Restores saved window positions for matching active application windows.
    Matches primarily on process name (e.g. code.exe, chrome.exe) and secondarily on title.
    """
    clean_name = str(name).strip().lower()
    profile = get_profile(clean_name)
    if not profile:
        return False, f"Profile '{clean_name}' not found.", []

    saved_windows = profile.get("windows", [])
    if not saved_windows:
        return False, f"Profile '{clean_name}' has no recorded windows.", []

    import win32gui
    import win32con

    current_windows = windows_tools.find_windows()
    matched = []
    unmatched = []

    # Map current windows by proc_name and title
    available_hwnds = set()
    for w in current_windows:
        hwnd = w.get("hwnd")
        if hwnd and win32gui.IsWindow(hwnd):
            available_hwnds.add(hwnd)

    for item in saved_windows:
        target_proc = item.get("proc_name", "").lower()
        target_title = item.get("title", "").lower()
        rect = item.get("rect", {})
        rx = rect.get("left", 0)
        ry = rect.get("top", 0)
        rw = rect.get("width", 800)
        rh = rect.get("height", 600)

        best_hwnd = None
        for w in current_windows:
            hw = w.get("hwnd")
            if hw not in available_hwnds:
                continue
            cur_proc = (w.get("proc_name") or "").lower()
            cur_title = (w.get("title") or "").lower()

            if cur_proc == target_proc:
                if target_title and target_title in cur_title:
                    best_hwnd = hw
                    break
                elif best_hwnd is None:
                    best_hwnd = hw

        if best_hwnd:
            available_hwnds.remove(best_hwnd)
            try:
                # Restore if minimized
                if win32gui.IsIconic(best_hwnd):
                    win32gui.ShowWindow(best_hwnd, win32con.SW_RESTORE)
                # Position window
                flags = win32con.SWP_NOZORDER | win32con.SWP_NOACTIVATE | win32con.SWP_SHOWWINDOW
                win32gui.SetWindowPos(best_hwnd, 0, rx, ry, rw, rh, flags)
                matched.append({
                    "proc_name": target_proc,
                    "hwnd": best_hwnd,
                    "applied_rect": [rx, ry, rw, rh]
                })
            except Exception as e:
                logger.warning("Error repositioning hwnd %s for %s: %s", best_hwnd, target_proc, e)
        else:
            unmatched.append(target_proc)

    summary = f"Applied layout '{clean_name}': repositioned {len(matched)} window(s)."
    if unmatched:
        summary += f" Not running: {', '.join(set(unmatched))}."
    return True, summary, matched
