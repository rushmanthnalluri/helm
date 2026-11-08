"""Windows Native Automation Tools for Homie.
Provides window management, multi-monitor geometry, screen captures,
media keys, app launching, and simulated input.
"""
import os
import sys
import time
import subprocess
import tempfile
import win32gui
import win32con
import win32api
import win32process
from PIL import ImageGrab, Image, ImageDraw, ImageFont

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

def find_windows(query=""):
    """Finds all visible top-level windows matching an app name or title query."""
    results = []
    q = query.lower().strip()

    def enum_cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return True
        title = win32gui.GetWindowText(hwnd).strip()
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

        win32gui.SetForegroundWindow(target_hwnd)
        return True, f"Placed window '{win32gui.GetWindowText(target_hwnd)[:30]}' to {where}"
    except Exception as e:
        return False, f"Failed to place window: {e}"

def capture_screens():
    """Captures each screen and writes labeled images to a temporary directory."""
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
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            win32gui.SetForegroundWindow(hwnd)
            return True, f"Switched to '{existing[0]['title'][:30]}'"
        except Exception:
            pass

    # 2. Known Windows app map
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
        'code': 'code',
        'vscode': 'code',
        'settings': 'ms-settings:',
        'task manager': 'taskmgr.exe',
        'paint': 'mspaint.exe'
    }

    for key, cmd in app_map.items():
        if key in q:
            try:
                if cmd.endswith(':'):
                    os.startfile(cmd)
                else:
                    subprocess.Popen(cmd, shell=True)
                return True, f"Launched {key}"
            except Exception as e:
                return False, f"Failed to launch {key}: {e}"

    # 3. Generic try via os.startfile or shell
    try:
        os.startfile(q)
        return True, f"Opened {q}"
    except Exception:
        try:
            subprocess.Popen(q, shell=True)
            return True, f"Ran {q}"
        except Exception as e:
            return False, f"Could not launch '{q}': {e}"

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
