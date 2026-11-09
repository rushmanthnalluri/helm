"""Windows Native Automation Tools for Homie.
Provides window management, multi-monitor geometry, screen captures,
media keys, app launching, and simulated input.
"""
import os
import sys
import time
import subprocess
import tempfile
import re
from typing import Dict, Any, Tuple, List
import win32gui
import win32con
import win32api
import win32process
from PIL import ImageGrab, Image, ImageDraw, ImageFont

VK_MAP: Dict[str, int] = {
    # Enter / Return
    "enter": 13, "return": 13, "cr": 13, "ret": 13, "{enter}": 13, "{return}": 13,
    "numpadenter": 13, "numpad_enter": 13,
    # Modifiers
    "ctrl": 17, "control": 17, "lctrl": 162, "rctrl": 163,
    "alt": 18, "menu": 18, "lalt": 164, "ralt": 165,
    "shift": 16, "lshift": 160, "rshift": 161,
    "win": 91, "windows": 91, "lwin": 91, "rwin": 92,
    # Letters
    **{chr(c).lower(): c for c in range(ord('A'), ord('Z') + 1)},
    # Digits
    **{str(d): ord('0') + d for d in range(10)},
    # F-keys
    **{f"f{i}": 111 + i for i in range(1, 13)},
    # Special keys
    "esc": 27, "escape": 27, "tab": 9, "backspace": 8, "space": 32,
    "delete": 46, "del": 46, "insert": 45, "home": 36, "end": 35,
    "pageup": 33, "pagedown": 34, "up": 38, "down": 40, "left": 37, "right": 39
}

def canonicalize_keyboard_arguments(arguments: Dict[str, Any]) -> Tuple[bool, bool, List[int], List[str]]:
    """Canonicalizes all keyboard and input arguments across all schemas into discrete Virtual-Key events.
    Guarantees:
    - NO substring or suffix tests (e.g. 'center', 'enterprise', 'return to sender' never trigger Enter).
    - Free-form prose strings ONLY check for literal newlines (\\n, \\r).
    - Catches key='\\n', text=['enter'], text=['\\n'], keycode=[13], vk=13.0, vk='0x0d'.
    - Catches synthetic Ctrl+Alt+P chord across key combinations, tokens, and numeric codes (e.g. [17, 18, 80]).
    - 'alt text for the ctrl panel' NEVER triggers Ctrl+Alt+P.
    Returns: (enter_detected: bool, ctrl_alt_p_detected: bool, vks: List[int], tokens: List[str])
    """
    KEY_FIELDS = (
        "key", "keys", "hotkey", "shortcut", "sequence",
        "vk", "keycode", "key_code", "keys_to_press", "chars", "input"
    )

    def _flatten(v) -> List[Any]:
        if v is None:
            return []
        if isinstance(v, (list, tuple, set)):
            res = []
            for item in v:
                res.extend(_flatten(item))
            return res
        return [v]

    def _parse_vk(raw, allow_decimal_str: bool = True) -> Optional[int]:
        if raw is None or raw == "":
            return None
        if isinstance(raw, (int, float)):
            try:
                return int(raw)
            except (ValueError, OverflowError):
                return None
        s = str(raw).strip().lower()
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                pass
        if allow_decimal_str:
            try:
                return int(float(s))
            except ValueError:
                pass
        return VK_MAP.get(s)

    detected_vks: List[int] = []
    tokens: List[str] = []
    enter_detected = False

    # 1. Text field inspection:
    # Free-form string prose ONLY checks for literal newlines (indicates form submit)
    # If text is a list/tuple: treat elements as individual key events / tokens
    # Avoid parsing numeric integer strings in free-form prose (e.g. typing "13" or "80" in text should not look like Enter or P).
    text_val = arguments.get("text")
    if text_val is not None:
        if isinstance(text_val, str):
            if "\n" in text_val or "\r" in text_val:
                enter_detected = True
        else:
            flat_text = _flatten(text_val)
            for item in flat_text:
                if item is None:
                    continue
                if isinstance(item, (int, float)):
                    vk = int(item)
                    detected_vks.append(vk)
                    if vk in (13, 0x0D):
                        enter_detected = True
                    continue
                s_item = str(item)
                if "\n" in s_item or "\r" in s_item:
                    enter_detected = True
                    detected_vks.append(13)
                    continue
                vk = _parse_vk(item, allow_decimal_str=False)
                if vk is not None:
                    detected_vks.append(vk)
                    if vk in (13, 0x0D):
                        enter_detected = True
                s_clean = s_item.strip().lower()
                tokens.append(s_clean)
                if s_clean in ("enter", "return", "{enter}", "{return}", "cr", "ret", "numpadenter", "numpad_enter"):
                    enter_detected = True
                    detected_vks.append(13)

    # 2. Key fields inspection (flattening all nested structures)
    for k_field in KEY_FIELDS:
        val = arguments.get(k_field)
        if val is None or val == "":
            continue
        flat_items = _flatten(val)
        for raw_item in flat_items:
            if raw_item is None or raw_item == "":
                continue

            # Check for unstripped newline / carriage return
            str_item = str(raw_item)
            if "\n" in str_item or "\r" in str_item:
                enter_detected = True
                detected_vks.append(13)

            # Try parsing directly as VK code
            vk = _parse_vk(raw_item)
            if vk is not None:
                detected_vks.append(vk)
                if vk in (13, 0x0D):
                    enter_detected = True

            # If string contains delimiter (+, -, space, comma), parse compound chord
            if isinstance(raw_item, str):
                raw_lower = raw_item.strip().lower()
                tokens.append(raw_lower)
                parts = [p.strip().lower() for p in re.split(r'[\+,\s\-]+', raw_lower) if p.strip()]
                for p in parts:
                    tokens.append(p)
                    part_vk = _parse_vk(p)
                    if part_vk is not None:
                        detected_vks.append(part_vk)
                        if part_vk in (13, 0x0D):
                            enter_detected = True

    # 3. Exact Virtual-Key chord matching for Ctrl + Alt + P
    # Modifiers: Ctrl (17, 162, 163), Alt (18, 164, 165), P (80, 0x50)
    has_ctrl = any(vk in detected_vks for vk in (17, 162, 163))
    has_alt = any(vk in detected_vks for vk in (18, 164, 165))
    has_p = (80 in detected_vks)

    token_set = set(tokens)
    has_ctrl_token = bool({"ctrl", "control", "lctrl", "rctrl"}.intersection(token_set))
    has_alt_token = bool({"alt", "menu", "lalt", "ralt"}.intersection(token_set))
    has_p_token = bool({"p"}.intersection(token_set))

    ctrl_alt_p_detected = (has_ctrl and has_alt and has_p) or (has_ctrl_token and has_alt_token and has_p_token)

    return enter_detected, ctrl_alt_p_detected, detected_vks, tokens

def detect_blocked_system_chords(detected_vks: List[int], tokens: List[str]) -> Optional[str]:
    """Detects dangerous system hotkey chords that bypass desktop confinement or trigger OS prompts.
    Explicitly blocks:
    - EVERY chord containing a Windows key (Win+*, Win+1..9, Win+E, Win+S, Win+I, Win+R, Win+X, etc.)
    - Alt+Tab, Alt+Space, Alt+F4
    - Ctrl+Shift+Esc, Ctrl+Alt+Del, Ctrl+Esc, Ctrl+Shift+Enter
    """
    token_set = set(t.lower() for t in tokens)

    has_win = any(vk in detected_vks for vk in (91, 92)) or bool({"win", "windows", "lwin", "rwin", "super", "cmd"}.intersection(token_set))
    has_alt = any(vk in detected_vks for vk in (18, 164, 165)) or bool({"alt", "menu", "lalt", "ralt"}.intersection(token_set))
    has_ctrl = any(vk in detected_vks for vk in (17, 162, 163)) or bool({"ctrl", "control", "lctrl", "rctrl"}.intersection(token_set))
    has_shift = any(vk in detected_vks for vk in (16, 160, 161)) or bool({"shift", "lshift", "rshift"}.intersection(token_set))
    has_r = (82 in detected_vks) or bool({"r"}.intersection(token_set)) or any("+r" in t for t in token_set)
    has_x = (88 in detected_vks) or bool({"x"}.intersection(token_set)) or any("+x" in t for t in token_set)
    has_f4 = (115 in detected_vks) or bool({"f4"}.intersection(token_set)) or any("+f4" in t for t in token_set)
    has_esc = (27 in detected_vks) or bool({"esc", "escape"}.intersection(token_set)) or any("+esc" in t for t in token_set)
    has_del = (46 in detected_vks) or bool({"del", "delete"}.intersection(token_set)) or any("+del" in t for t in token_set)
    has_tab = (9 in detected_vks) or bool({"tab"}.intersection(token_set)) or any("+tab" in t for t in token_set)
    has_space = (32 in detected_vks) or bool({"space"}.intersection(token_set)) or any("+space" in t for t in token_set)
    has_enter = (13 in detected_vks) or bool({"enter", "return"}.intersection(token_set)) or any("+enter" in t for t in token_set)

    # 1. Explicit high-risk chords
    if has_win and has_r:
        return "Win+R"
    if has_win and has_x:
        return "Win+X"
    if has_alt and has_f4:
        return "Alt+F4"
    if has_alt and has_tab:
        return "Alt+Tab"
    if has_alt and has_space:
        return "Alt+Space"
    if has_ctrl and has_shift and has_esc:
        return "Ctrl+Shift+Esc"
    if has_ctrl and has_alt and has_del:
        return "Ctrl+Alt+Del"
    if has_ctrl and has_esc:
        return "Ctrl+Esc"
    if has_ctrl and has_shift and has_enter:
        return "Ctrl+Shift+Enter"

    # 2. Total Win-Key Chord Denial: Deny ANY chord containing a Windows key
    if has_win:
        win_vks = {91, 92}
        win_tokens = {"win", "windows", "lwin", "rwin", "super", "cmd"}
        other_vks = [vk for vk in detected_vks if vk not in win_vks]
        sub_tokens = set()
        for t in token_set:
            for part in t.split("+"):
                p = part.strip()
                if p and p not in win_tokens:
                    sub_tokens.add(p)
        if other_vks or sub_tokens:
            tok_name = sorted(sub_tokens)[0].upper() if sub_tokens else (chr(other_vks[0]).upper() if 32 <= other_vks[0] <= 126 else str(other_vks[0]))
            return f"Win+{tok_name}"

    return None

def get_browser_active_domain(hwnd: Optional[int] = None) -> Optional[str]:
    """Inspects active browser window via Windows UI Automation (UIA) to extract true URL hostname.
    Top-level window constraint: Search descendants of hwnd ONLY.
    Never falls back to desktop root uia.EditControl to prevent matching inputs on other windows or web pages.
    Filters browser chrome toolbar controls specifically: Chrome_OmniboxView, OmniboxViewViews, addressEditBox, urlbar-input.
    """
    if not hwnd:
        fg = get_foreground_window()
        hwnd = fg.get("hwnd") if fg else None
    if not hwnd:
        return None

    try:
        import uiautomation as uia
        import urllib.parse

        try:
            window_ctrl = uia.ControlFromHandle(hwnd)
        except Exception:
            window_ctrl = None

        if not window_ctrl:
            return None

        # Search descendants of hwnd ONLY (never desktop root)
        edit = None
        for class_name in ("Chrome_OmniboxView", "OmniboxViewViews"):
            try:
                cand = window_ctrl.EditControl(searchDepth=10, ClassName=class_name)
                if cand.Exists(0.05):
                    edit = cand
                    break
            except Exception:
                pass

        if not edit or not edit.Exists(0.01):
            for auto_id in ("addressEditBox", "urlbar-input"):
                try:
                    cand = window_ctrl.EditControl(searchDepth=10, AutomationId=auto_id)
                    if cand.Exists(0.05):
                        edit = cand
                        break
                except Exception:
                    pass

        if not edit or not edit.Exists(0.01):
            try:
                cand = window_ctrl.EditControl(searchDepth=10, SubName="Address")
                if cand.Exists(0.05):
                    edit = cand
            except Exception:
                pass

        if edit and edit.Exists(0.01):
            val = edit.GetValuePattern().Value if hasattr(edit, 'GetValuePattern') else ""
            if val:
                val = str(val).strip()
                if not val.startswith(("http://", "https://")):
                    val = "https://" + val
                parsed = urllib.parse.urlparse(val)
                return parsed.hostname
    except Exception as e:
        logger.debug("UIA browser domain inspection error: %s", e)
    return None

def enable_dpi_awareness():
    """Sets per-monitor DPI awareness (V2) to guarantee exact multi-monitor coordinate precision."""
    try:
        import ctypes
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            import ctypes
            # PROCESS_PER_MONITOR_DPI_AWARE = 2
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

def ensure_desktop_attached():
    """Ensures the current thread and process are attached to the interactive user desktop (WinSta0\\Default).
    Crucial for Windows services, background terminal tasks, and child processes to interact with desktop windows.
    """
    enable_dpi_awareness()
    try:
        import ctypes
        u = ctypes.windll.user32
        h_winsta = u.OpenWindowStationW('WinSta0', False, 0x10000000)
        if h_winsta:
            u.SetProcessWindowStation(h_winsta)
        h_desk = u.OpenDesktopW('Default', 0, False, 0x10000000)
        if h_desk:
            u.SetThreadDesktop(h_desk)
    except Exception:
        pass

# Ensure DPI awareness at load time
enable_dpi_awareness()

def force_foreground_window(hwnd):
    """Guarantees bringing a window to the true foreground on Windows 10/11,
    bypassing foreground lock timeouts even from background threads or daemons.
    """
    if not hwnd or not win32gui.IsWindow(hwnd):
        return False
    try:
        import ctypes
        u = ctypes.windll.user32
        ensure_desktop_attached()

        # Restore window if minimized
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)

        # Attach thread input to overcome LockSetForegroundWindow restrictions
        cur_fg = win32gui.GetForegroundWindow()
        cur_tid = 0
        if cur_fg and win32gui.IsWindow(cur_fg):
            cur_tid, _ = win32process.GetWindowThreadProcessId(cur_fg)
        our_tid = win32api.GetCurrentThreadId()

        attached = False
        if cur_tid and cur_tid != our_tid:
            attached = bool(u.AttachThreadInput(cur_tid, our_tid, True))

        # Alt key tap trick clears Windows OS foreground lock timer
        u.keybd_event(win32con.VK_MENU, 0, 0, 0)
        u.keybd_event(win32con.VK_MENU, 0, win32con.KEYEVENTF_KEYUP, 0)

        u.BringWindowToTop(hwnd)
        u.SetForegroundWindow(hwnd)

        if attached:
            u.AttachThreadInput(cur_tid, our_tid, False)

        return True
    except Exception:
        try:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(hwnd)
            return True
        except Exception:
            return False

def get_monitors():
    """Returns a list of connected monitors with screen and work area dimensions."""
    monitors = []
    try:
        raw_monitors = win32api.EnumDisplayMonitors()
        for i, m in enumerate(raw_monitors):
            info = win32api.GetMonitorInfo(m[0])
            rc_monitor = info['rcMonitor']  # (left, top, right, bottom)
            rc_work = info['rcWork']        # excludes taskbar
            is_primary = bool(info.get('Flags', 0) & win32con.MONITORINFOF_PRIMARY)
            monitors.append({
                'index': i,
                'handle': m[0],
                'rect': rc_monitor,
                'work': rc_work,
                'x': rc_work[0],
                'y': rc_work[1],
                'width': rc_work[2] - rc_work[0],
                'height': rc_work[3] - rc_work[1],
                'primary': is_primary,
                'name': f"Display {i + 1}" + (" (Primary)" if is_primary else "")
            })
    except Exception as e:
        # Fallback to single primary monitor
        sw = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
        sh = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
        monitors.append({
            'index': 0,
            'handle': None,
            'rect': (0, 0, sw, sh),
            'work': (0, 0, sw, sh),
            'x': 0,
            'y': 0,
            'width': sw,
            'height': sh,
            'primary': True,
            'name': 'Primary Display'
        })
    return monitors

def get_foreground_window():
    """Gets info about the currently active foreground window."""
    try:
        hwnd = win32gui.GetForegroundWindow()
        if not hwnd or not win32gui.IsWindow(hwnd):
            return None
        title = win32gui.GetWindowText(hwnd)
        rect = win32gui.GetWindowRect(hwnd)
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        proc_name = ""
        try:
            import psutil
            proc_name = psutil.Process(pid).name()
        except Exception:
            pass
        return {
            'hwnd': hwnd,
            'title': title,
            'pid': pid,
            'proc_name': proc_name,
            'rect': rect
        }
    except Exception:
        return None

def get_window_process_info(hwnd):
    """Retrieves process ID, executable name, and full image path for any HWND."""
    if not hwnd or not win32gui.IsWindow(hwnd):
        return {'pid': 0, 'proc_name': '', 'exe_path': ''}
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        proc_name = ""
        exe_path = ""
        try:
            import psutil
            p = psutil.Process(pid)
            proc_name = p.name()
            exe_path = p.exe()
        except Exception:
            pass
        return {'pid': pid, 'proc_name': proc_name, 'exe_path': exe_path}
    except Exception:
        return {'pid': 0, 'proc_name': '', 'exe_path': ''}

PROHIBITED_PROCESS_IMAGES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe", "bash.exe", "wsl.exe",
    "python.exe", "pythonw.exe", "mshta.exe", "rundll32.exe", "cscript.exe",
    "wscript.exe", "regedit.exe", "mmc.exe", "telegram.exe", "consent.exe"
}

def is_prohibited_target_process(hwnd=None):
    """Evaluates whether an HWND (or current foreground window) belongs to a prohibited interpreter, shell, or security boundary."""
    target_hwnd = hwnd
    if not target_hwnd:
        target_hwnd = win32gui.GetForegroundWindow()
    if not target_hwnd:
        return False, "No active window"

    info = get_window_process_info(target_hwnd)
    proc_name = (info.get("proc_name") or "").lower()

    if proc_name in PROHIBITED_PROCESS_IMAGES:
        return True, f"Prohibited process image: '{proc_name}'"

    # Check for Windows Run Dialog (#32770 with title 'Run')
    try:
        cls_name = win32gui.GetClassName(target_hwnd)
        title = win32gui.GetWindowText(target_hwnd)
        if cls_name == "#32770" and title.lower() == "run":
            return True, "Prohibited system dialog: Windows Run Dialog"
    except Exception:
        pass

    return False, "Permitted target process"

def find_windows(query=""):
    """Finds all visible top-level windows matching an app name or title query."""
    ensure_desktop_attached()
    results = []
    q = query.lower().strip()

    def enum_cb(hwnd, _):
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            title = ""
            try:
                title = win32gui.GetWindowText(hwnd).strip()
            except Exception:
                pass
            if not title:
                return True

            # Ignore tooltips, cloaked windows, or tiny helper windows
            style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
            ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            if ex_style & win32con.WS_EX_TOOLWINDOW:
                return True

            rect = win32gui.GetWindowRect(hwnd)
            w, h = rect[2] - rect[0], rect[3] - rect[1]
            if w < 100 or h < 100:
                return True

            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            proc_name = ""
            try:
                import psutil
                proc_name = psutil.Process(pid).name()
            except Exception:
                pass

            match = False
            if not q:
                match = True
            elif q in title.lower() or (proc_name and q in proc_name.lower()):
                match = True

            if match:
                results.append({
                    'hwnd': hwnd,
                    'title': title,
                    'proc_name': proc_name,
                    'pid': pid,
                    'rect': rect
                })
        except Exception:
            pass
        return True

    try:
        win32gui.EnumWindows(enum_cb, None)
    except Exception:
        pass
    return results

def place_window(app_or_title="", where="full", monitor_index=0):
    """
    Moves and snaps a window to a specified position on a monitor.
    where: 'left', 'right', 'full', 'center', 'maximize', 'minimize'
    """
    monitors = get_monitors()
    target_monitor = monitors[0]
    if isinstance(monitor_index, int) and 0 <= monitor_index < len(monitors):
        target_monitor = monitors[monitor_index]

    mx = target_monitor['x']
    my = target_monitor['y']
    mw = target_monitor['width']
    mh = target_monitor['height']

    target_hwnd = None
    if app_or_title:
        wins = find_windows(app_or_title)
        if wins:
            target_hwnd = wins[0]['hwnd']
    if not target_hwnd:
        fg = get_foreground_window()
        if fg:
            target_hwnd = fg['hwnd']

    if not target_hwnd:
        return False, "No window found to place."

    where = where.lower().strip()
    try:
        # Restore if minimized or maximized
        if where not in ('minimize', 'maximize'):
            win32gui.ShowWindow(target_hwnd, win32con.SW_RESTORE)

        if where == 'left':
            nx, ny, nw, nh = mx, my, mw // 2, mh
            win32gui.MoveWindow(target_hwnd, nx, ny, nw, nh, True)
        elif where == 'right':
            nx, ny, nw, nh = mx + mw // 2, my, mw - (mw // 2), mh
            win32gui.MoveWindow(target_hwnd, nx, ny, nw, nh, True)
        elif where == 'center':
            nw = min(int(mw * 0.75), 1400)
            nh = min(int(mh * 0.8), 900)
            nx = mx + (mw - nw) // 2
            ny = my + (mh - nh) // 2
            win32gui.MoveWindow(target_hwnd, nx, ny, nw, nh, True)
        elif where in ('full', 'maximize'):
            win32gui.ShowWindow(target_hwnd, win32con.SW_MAXIMIZE)
        elif where == 'minimize':
            win32gui.ShowWindow(target_hwnd, win32con.SW_MINIMIZE)
        else:
            nx, ny, nw, nh = mx, my, mw, mh
            win32gui.MoveWindow(target_hwnd, nx, ny, nw, nh, True)

        force_foreground_window(target_hwnd)
        return True, f"Placed window '{win32gui.GetWindowText(target_hwnd)[:30]}' to {where}"
    except Exception as e:
        return False, f"Failed to place window: {e}"

def capture_screens():
    """Captures each screen and writes labeled images to a temporary directory."""
    ensure_desktop_attached()
    monitors = get_monitors()
    captured_files = []
    tmp_dir = os.path.join(tempfile.gettempdir(), 'homie-screens')
    os.makedirs(tmp_dir, exist_ok=True)

    # 1. Try mss capture
    try:
        import mss
        with mss.MSS() as sct:
            # sct.monitors[1:] are individual displays; [0] is virtual bounding box
            screen_mons = sct.monitors[1:] if len(sct.monitors) > 1 else sct.monitors
            for i, mon in enumerate(screen_mons):
                try:
                    sct_img = sct.grab(mon)
                    path = os.path.join(tmp_dir, f"screen-{i}.png")
                    mss.tools.to_png(sct_img.rgb, sct_img.size, output=path)
                    captured_files.append(path)
                except Exception:
                    pass
    except Exception:
        pass

    # 2. Try PIL ImageGrab
    if not captured_files:
        try:
            for m in monitors:
                idx = m['index']
                rect = m['rect']
                img = ImageGrab.grab(bbox=rect, all_screens=True)
                path = os.path.join(tmp_dir, f"screen-{idx}.png")
                img.save(path, format='PNG')
                captured_files.append(path)
        except Exception:
            pass

    # 3. Fallback: if desktop is locked or headless, generate labeled snapshot canvas with window context
    if not captured_files:
        try:
            fg = get_foreground_window()
            fg_title = fg['title'] if fg else "Desktop"
            for m in monitors:
                idx = m['index']
                w = m.get('width', 1600)
                h = m.get('height', 900)
                img = Image.new('RGB', (w, h), color=(30, 30, 35))
                draw = ImageDraw.Draw(img)
                draw.rectangle([20, 20, w - 20, h - 20], outline=(70, 70, 80), width=2)
                draw.rectangle([40, 40, w - 40, 100], fill=(45, 45, 55))
                label = f"Display {idx + 1}: {w}x{h} | Active Window: {fg_title}"
                draw.text((60, 60), label, fill=(240, 240, 245))
                path = os.path.join(tmp_dir, f"screen-{idx}.png")
                img.save(path, format='PNG')
                captured_files.append(path)
        except Exception:
            pass

    return captured_files

def control_media(action):
    """Simulates Windows media hardware keys."""
    VK_MEDIA_NEXT_TRACK = 0xB0
    VK_MEDIA_PREV_TRACK = 0xB1
    VK_MEDIA_STOP = 0xB2
    VK_MEDIA_PLAY_PAUSE = 0xB3
    VK_VOLUME_MUTE = 0xAD
    VK_VOLUME_DOWN = 0xAE
    VK_VOLUME_UP = 0xAF

    key_map = {
        'play': VK_MEDIA_PLAY_PAUSE,
        'pause': VK_MEDIA_PLAY_PAUSE,
        'play_pause': VK_MEDIA_PLAY_PAUSE,
        'playpause': VK_MEDIA_PLAY_PAUSE,
        'toggle': VK_MEDIA_PLAY_PAUSE,
        'next': VK_MEDIA_NEXT_TRACK,
        'prev': VK_MEDIA_PREV_TRACK,
        'previous': VK_MEDIA_PREV_TRACK,
        'stop': VK_MEDIA_STOP,
        'mute': VK_VOLUME_MUTE,
        'volup': VK_VOLUME_UP,
        'voldown': VK_VOLUME_DOWN,
    }

    vk = key_map.get(action.lower().replace(" ", "").replace("_", ""))
    if not vk:
        return False, f"Unknown media action: {action}"

    try:
        win32api.keybd_event(vk, 0, 0, 0)
        time.sleep(0.05)
        win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
        return True, f"Triggered media key for '{action}'"
    except Exception as e:
        return False, f"Media control error: {e}"

def launch_app(name_or_query):
    """Intelligently launches or activates common Windows applications."""
    q = name_or_query.lower().strip()
    
    # 1. Check if matching window is already open; if so, bring it forward
    existing = find_windows(q)
    if existing:
        try:
            hwnd = existing[0]['hwnd']
            force_foreground_window(hwnd)
            return True, f"Switched to '{existing[0]['title'][:30]}'"
        except Exception:
            pass

    # 2. Known Windows app and website map
    app_map = {
        'notepad': 'notepad.exe',
        'calc': 'calc.exe',
        'calculator': 'calc.exe',
        'terminal': 'wt.exe',
        'cmd': 'cmd.exe',
        'command prompt': 'cmd.exe',
        'powershell': 'powershell.exe',
        'explorer': 'explorer.exe',
        'files': 'explorer.exe',
        'chrome': 'chrome',
        'edge': 'msedge',
        'firefox': 'firefox',
        'spotify': 'spotify:',
        'whatsapp': 'whatsapp:',
        'telegram': 'tg:',
        'discord': 'discord:',
        'slack': 'slack:',
        'teams': 'msteams:',
        'zoom': 'zoommtg:',
        'steam': 'steam:',
        'code': 'code',
        'vscode': 'code',
        'settings': 'ms-settings:',
        'task manager': 'taskmgr.exe',
        'paint': 'mspaint.exe',
        'camera': 'microsoft.windows.camera:',
        'clock': 'ms-clock:',
        'word': 'winword.exe',
        'excel': 'excel.exe',
        'powerpoint': 'powerpnt.exe',
        'vlc': 'vlc.exe',
        'youtube': 'https://www.youtube.com',
        'google': 'https://www.google.com',
        'gmail': 'https://mail.google.com',
        'github': 'https://github.com',
        'reddit': 'https://reddit.com',
        'twitter': 'https://x.com',
        'netflix': 'https://www.netflix.com',
        'chatgpt': 'https://chatgpt.com'
    }

    for key, cmd in app_map.items():
        if key in q:
            try:
                if cmd.startswith(('http://', 'https://')):
                    import webbrowser
                    webbrowser.open(cmd)
                    return True, f"Opened {key} in browser"
                elif cmd.endswith(':'):
                    try:
                        os.startfile(cmd)
                        return True, f"Launched {key}"
                    except Exception:
                        web_fallbacks = {
                            'whatsapp': 'https://web.whatsapp.com',
                            'telegram': 'https://web.telegram.org',
                            'spotify': 'https://open.spotify.com',
                            'discord': 'https://discord.com/app',
                            'netflix': 'https://www.netflix.com'
                        }
                        if key in web_fallbacks:
                            import webbrowser
                            webbrowser.open(web_fallbacks[key])
                            return True, f"Opened {key} in your browser."
                        raise
                else:
                    import shutil
                    if shutil.which(cmd):
                        subprocess.Popen([cmd], shell=False)
                        return True, f"Launched {key}"
                    else:
                        subprocess.Popen(cmd, shell=True)
                        return True, f"Launched {key}"
            except Exception as e:
                return False, f"Failed to launch {key}: {e}"

    # 3. URL or generic target
    if q.startswith(('http://', 'https://', 'www.')):
        import webbrowser
        url = q if q.startswith('http') else f"https://{q}"
        webbrowser.open(url)
        return True, f"Opened {url}"

    # 4. Check if command exists in PATH before calling Popen
    import shutil
    cmd_path = shutil.which(q) or shutil.which(f"{q}.exe")
    if cmd_path:
        try:
            subprocess.Popen([cmd_path])
            return True, f"Launched {q}"
        except Exception as e:
            return False, f"Failed to launch '{q}': {e}"

    # 5. Try URI protocol via os.startfile
    try:
        os.startfile(q)
        return True, f"Opened {q}"
    except Exception:
        pass

    return False, f"Could not find or launch application '{q}' on your PC."

def read_window_text(app_query=""):
    """Reads titles and texts from the target or active window."""
    target_hwnd = None
    if app_query:
        wins = find_windows(app_query)
        if wins:
            target_hwnd = wins[0]['hwnd']
    if not target_hwnd:
        fg = get_foreground_window()
        if fg:
            target_hwnd = fg['hwnd']

    if not target_hwnd:
        return "No active window found."

    title = win32gui.GetWindowText(target_hwnd)
    rect = win32gui.GetWindowRect(target_hwnd)
    texts = [f"Window: '{title}' at {rect}"]

    def enum_child_cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            t = win32gui.GetWindowText(hwnd).strip()
            if t and len(t) > 1 and t not in texts:
                texts.append(f"  - {t}")
        return True

    try:
        win32gui.EnumChildWindows(target_hwnd, enum_child_cb, None)
    except Exception:
        pass

    return "\n".join(texts[:50])

def close_app(app_name):
    """Gracefully closes a running application by name, window title, or process name."""
    ensure_desktop_attached()
    wins = find_windows(app_name)
    if wins:
        closed = 0
        for w in wins:
            try:
                win32gui.PostMessage(w['hwnd'], win32con.WM_CLOSE, 0, 0)
                closed += 1
            except Exception:
                pass
        if closed:
            return True, f"Closed {app_name} window ({closed} instance(s))."

    # Common process names for Windows apps
    proc_aliases = {
        'whatsapp': ['WhatsApp.Root.exe', 'WhatsApp.exe'],
        'telegram': ['Telegram.exe'],
        'spotify': ['Spotify.exe'],
        'chrome': ['chrome.exe'],
        'edge': ['msedge.exe'],
        'code': ['Code.exe'],
        'vscode': ['Code.exe'],
        'discord': ['Discord.exe'],
        'calc': ['CalculatorApp.exe', 'calc.exe'],
        'calculator': ['CalculatorApp.exe', 'calc.exe'],
        'terminal': ['WindowsTerminal.exe', 'wt.exe'],
        'notepad': ['Notepad.exe'],
    }

    clean_name = app_name.lower().replace(".exe", "").strip()
    targets = proc_aliases.get(clean_name, [f"{clean_name}.exe"])

    terminated = False
    for exe in targets:
        try:
            res = subprocess.run(f"taskkill /F /IM {exe} /T", shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                terminated = True
        except Exception:
            pass

    if terminated:
        return True, f"Closed {app_name}."

    return False, f"Could not find running window or process for '{app_name}'."

def play_youtube(query=""):
    """Opens YouTube and starts playback of the requested song, video, or playlist.
    Extracts the top video ID via YouTube search and launches Chrome/Edge with &autoplay=1,
    bringing the browser directly to the foreground.
    """
    import urllib.parse
    import urllib.request
    import re

    q = (query or "").strip()
    target_url = "https://www.youtube.com"

    if q:
        try:
            search_url = f"https://www.youtube.com/results?search_query={urllib.parse.quote(q)}"
            req = urllib.request.Request(search_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
            ids = re.findall(r'/watch\?v=([a-zA-Z0-9_-]{11})', html)
            if ids:
                target_url = f"https://www.youtube.com/watch?v={ids[0]}&autoplay=1"
            else:
                target_url = search_url
        except Exception:
            target_url = f"https://www.youtube.com/results?search_query={urllib.parse.quote(q)}"

    # Search for Chrome or Edge browser executable
    browser_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    browser_bin = None
    for p in browser_paths:
        if os.path.exists(p):
            browser_bin = p
            break

    try:
        if browser_bin:
            subprocess.Popen([browser_bin, target_url], shell=False)
        else:
            import webbrowser
            webbrowser.open(target_url)

        # Give browser time to launch, then bring to foreground
        time.sleep(1.2)
        b_wins = find_windows("chrome") or find_windows("edge") or find_windows("youtube")
        if b_wins:
            force_foreground_window(b_wins[0]['hwnd'])

        action_desc = f"Playing '{q}'" if q else "Opened YouTube"
        return True, f"{action_desc} on YouTube: {target_url}"
    except Exception as e:
        return False, f"Failed to open YouTube: {e}"

def send_chat_message(app_name, recipient="", message=""):
    """Automates sending a chat message to a contact in WhatsApp or Telegram on Windows."""
    # This low-level entry point is shared by the fast parser, AI tools, and
    # Telegram commands, so enforce the preference here rather than relying on
    # any individual caller to remember the policy.
    try:
        import homie
        if homie.get_prefs().get('safe', True):
            app_disp = "WhatsApp" if app_name.lower() == "whatsapp" else app_name.capitalize()
            return False, f"Blocked by Safe Mode. Turn Safe Mode off to send a {app_disp} message."
    except Exception as e:
        return False, f"Blocked: could not verify Safe Mode ({e})."

    import pyautogui
    import pyperclip
    import urllib.parse
    import re

    pyautogui.FAILSAFE = False
    ensure_desktop_attached()

    app_lower = app_name.lower().strip()
    recipient = (recipient or "").strip()
    message = (message or "").strip()

    # Launch or switch to application
    launch_app(app_lower)

    # Poll for window handle up to 3 seconds
    target_hwnd = None
    for _ in range(12):
        wins = find_windows(app_lower)
        if wins:
            target_hwnd = wins[0]['hwnd']
            break
        time.sleep(0.25)

    if target_hwnd:
        force_foreground_window(target_hwnd)
    time.sleep(0.8)

    try:
        if 'whatsapp' in app_lower:
            # If recipient is a direct phone number, use whatsapp protocol
            clean_phone = re.sub(r'[^\d+]', '', recipient)
            if clean_phone and len(clean_phone) >= 7 and message:
                try:
                    url = f"whatsapp://send?phone={clean_phone}&text={urllib.parse.quote(message)}"
                    os.startfile(url)
                    time.sleep(1.5)
                    if target_hwnd:
                        force_foreground_window(target_hwnd)
                    pyautogui.press('enter')
                    return True, f"Sent '{message}' to phone {clean_phone} on WhatsApp."
                except Exception:
                    pass

            # Focus and clear current selection
            pyautogui.press('esc')
            time.sleep(0.2)
            pyautogui.press('esc')
            time.sleep(0.2)

            if recipient:
                # Ctrl+F is universal Search Chats / Contacts in WhatsApp Desktop
                pyautogui.hotkey('ctrl', 'f')
                time.sleep(0.3)
                pyautogui.hotkey('ctrl', 'a')
                time.sleep(0.1)
                pyautogui.press('backspace')
                time.sleep(0.1)

                pyperclip.copy(recipient)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(1.0)  # Wait for contact search results to load

                # Down arrow to first match, then Enter to open conversation
                pyautogui.press('down')
                time.sleep(0.2)
                pyautogui.press('enter')
                time.sleep(0.8)

            if target_hwnd:
                force_foreground_window(target_hwnd)

            if message:
                pyperclip.copy(message)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(0.3)
                pyautogui.press('enter')

            target_desc = f" to {recipient}" if recipient else ""
            return True, f"Sent '{message}'{target_desc} on WhatsApp."

        elif 'telegram' in app_lower:
            pyautogui.press('esc')
            time.sleep(0.2)
            pyautogui.press('esc')
            time.sleep(0.2)

            if recipient:
                # Ctrl+K is universal Telegram contact / chat search
                pyautogui.hotkey('ctrl', 'k')
                time.sleep(0.3)
                pyautogui.hotkey('ctrl', 'a')
                time.sleep(0.1)
                pyautogui.press('backspace')
                time.sleep(0.1)

                pyperclip.copy(recipient)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(0.8)
                pyautogui.press('down')
                time.sleep(0.2)
                pyautogui.press('enter')
                time.sleep(0.6)

            if target_hwnd:
                force_foreground_window(target_hwnd)

            if message:
                pyperclip.copy(message)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(0.3)
                pyautogui.press('enter')

            target_desc = f" to {recipient}" if recipient else ""
            return True, f"Sent '{message}'{target_desc} on Telegram."

        return False, f"Unsupported messaging app: {app_name}"
    except Exception as e:
        return False, f"Failed to send message in {app_name}: {e}"

def get_system_vitals():
    """Gathers real-time Windows PC health vitals using standard kernel32 & ctypes."""
    import ctypes
    import shutil

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ('dwLength', ctypes.c_uint32),
            ('dwMemoryLoad', ctypes.c_uint32),
            ('ullTotalPhys', ctypes.c_uint64),
            ('ullAvailPhys', ctypes.c_uint64),
            ('ullTotalPageFile', ctypes.c_uint64),
            ('ullAvailPageFile', ctypes.c_uint64),
            ('ullTotalVirtual', ctypes.c_uint64),
            ('ullAvailVirtual', ctypes.c_uint64),
            ('ullAvailExtendedVirtual', ctypes.c_uint64),
        ]

    class SYSTEM_POWER_STATUS(ctypes.Structure):
        _fields_ = [
            ('ACLineStatus', ctypes.c_byte),
            ('BatteryFlag', ctypes.c_byte),
            ('BatteryLifePercent', ctypes.c_byte),
            ('SystemStatusFlag', ctypes.c_byte),
            ('BatteryLifeTime', ctypes.c_uint32),
            ('BatteryFullLifeTime', ctypes.c_uint32),
        ]

    # Memory
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    ram_pct = stat.dwMemoryLoad
    ram_avail_gb = stat.ullAvailPhys / (1024 ** 3)
    ram_total_gb = stat.ullTotalPhys / (1024 ** 3)

    # Disk
    disk = shutil.disk_usage("C:\\")
    disk_free_gb = disk.free / (1024 ** 3)
    disk_total_gb = disk.total / (1024 ** 3)

    # Battery
    sps = SYSTEM_POWER_STATUS()
    bat_str = "Desktop (AC)"
    if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
        if sps.BatteryLifePercent != 255:
            plugged = "🔌 Plugged in" if sps.ACLineStatus == 1 else "🔋 On battery"
            bat_str = f"{sps.BatteryLifePercent}% ({plugged})"

    # Uptime
    uptime_hours = (ctypes.windll.kernel32.GetTickCount64() / 1000.0) / 3600.0

    # Active window
    fg = get_foreground_window()
    fg_title = fg['title'][:40] if fg else "Desktop"

    return {
        'ram_pct': ram_pct,
        'ram_avail_gb': round(ram_avail_gb, 1),
        'ram_total_gb': round(ram_total_gb, 1),
        'disk_free_gb': round(disk_free_gb, 1),
        'disk_total_gb': round(disk_total_gb, 1),
        'battery': bat_str,
        'uptime_hours': round(uptime_hours, 1),
        'active_window': fg_title
    }

def get_clipboard_text():
    """Reads text from the Windows clipboard safely."""
    try:
        import pyperclip
        return pyperclip.paste() or ""
    except Exception:
        return ""

def set_clipboard_text(text):
    """Writes text to the Windows clipboard."""
    try:
        import pyperclip
        pyperclip.copy(str(text))
        return True, f"Copied {len(str(text))} characters to Windows clipboard."
    except Exception as e:
        return False, f"Failed to copy to clipboard: {e}"

def list_downloads(limit=10):
    """Returns recent files in the user's Downloads folder."""
    dl_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(dl_path):
        return []
    entries = []
    try:
        for name in os.listdir(dl_path):
            full = os.path.join(dl_path, name)
            if os.path.isfile(full):
                stat = os.stat(full)
                size_mb = stat.st_size / (1024 * 1024)
                mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(stat.st_mtime))
                entries.append({
                    'name': name,
                    'path': full,
                    'size_mb': round(size_mb, 2),
                    'mtime': mtime,
                    'raw_mtime': stat.st_mtime
                })
        entries.sort(key=lambda x: x['raw_mtime'], reverse=True)
    except Exception:
        pass
    return entries[:limit]

def execute_safe_command(command, timeout=20):
    """Executes a system shell command safely with guardrails against destructive commands."""
    cmd = (command or "").strip()
    if not cmd:
        return False, "No command provided."

    blocked_patterns = [
        # Destructive file/disk/system actions
        r'\b(rmdir|rd)\s+/[sS]\b',
        r'\bdel\s+.*(/[sS]|/[fF])\b',
        r'\bformat\s+[a-zA-Z]:',
        r'\b(diskpart|bcdedit)\b',
        r'\breg\s+delete\b',
        r'\bshutdown\s+[-/][a-zA-Z]',
        r'\b(takeown|icacls)\b.*(/[gG]|grant)',
        # PowerShell evasion & execution bypasses
        r'-(?:e|enc|encodedcommand)\b',
        r'\b(invoke-expression|iex)\b',
        r'\b(downloadstring|downloadfile)\b',
        r'\bi(?:wr|rm)\s+.*\|\s*iex\b',
        r'\bcertutil\b.*-(?:decode|urlcache)',
        r'\bbitsadmin\b.*transfer',
        r'-executionpolicy\s+bypass',
        # Chained shell executions and metacharacters
        r'\|\s*(?:powershell|cmd|sh|bash)\b',
        r'[;&|`$]|\r|\n|\x00'
    ]
    import re
    for pattern in blocked_patterns:
        if re.search(pattern, cmd, re.I):
            return False, f"Blocked unsafe command matching security guardrail: '{pattern}'"

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=os.path.expanduser("~"))
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        out = stdout or stderr or "(Command completed with no output)"
        if len(out) > 3500:
            out = out[:3500] + "\n... [Remaining output truncated]"
        ok = (proc.returncode == 0)
        return ok, out
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout} seconds."
    except Exception as e:
        return False, f"Execution failed: {e}"

PROTECTED_PROCESS_NAMES = {
    'winlogon.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
    'explorer.exe', 'smss.exe', 'svchost.exe', 'system', 'registry', 'fontdrvhost.exe'
}

def get_top_processes(sort_by="memory", limit=8):
    """Retrieves top resource-consuming processes on Windows."""
    import psutil
    proc_list = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent', 'memory_info']):
        try:
            info = proc.info
            mem_pct = info.get('memory_percent') or 0.0
            cpu_pct = info.get('cpu_percent') or 0.0
            mem_info = info.get('memory_info')
            mem_mb = round(mem_info.rss / (1024 * 1024), 1) if mem_info else 0.0
            proc_list.append({
                'pid': info['pid'],
                'name': info.get('name') or 'unknown',
                'mem_pct': round(mem_pct, 1),
                'mem_mb': mem_mb,
                'cpu_pct': round(cpu_pct, 1)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    sort_key = 'mem_pct' if sort_by == 'memory' else 'cpu_pct'
    proc_list.sort(key=lambda p: p[sort_key], reverse=True)
    return proc_list[:limit]

def kill_process_by_pid(pid):
    """Safely terminates a process by PID with OS protected process guardrails."""
    import psutil
    try:
        proc = psutil.Process(int(pid))
        pname = proc.name().lower()
        if pname in PROTECTED_PROCESS_NAMES:
            return False, f"Blocked: '{pname}' is a critical Windows system process and cannot be terminated."
        proc.terminate()
        return True, f"Terminated process '{pname}' (PID {pid})."
    except psutil.NoSuchProcess:
        return False, f"No running process found with PID {pid}."
    except psutil.AccessDenied:
        return False, f"Access denied terminating process PID {pid} (requires elevation)."
    except Exception as e:
        return False, f"Failed to terminate PID {pid}: {e}"

def get_idle_seconds():
    """Returns the number of seconds the user has been idle (no keyboard/mouse input)."""
    import ctypes
    from ctypes import wintypes
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
        tick_count = ctypes.windll.kernel32.GetTickCount()
        idle_ms = max(0, tick_count - lii.dwTime)
        return round(idle_ms / 1000.0, 1)
    return 0.0
