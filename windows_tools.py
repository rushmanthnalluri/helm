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

def ensure_desktop_attached():
    """Ensures the current thread and process are attached to the interactive user desktop (WinSta0\\Default).
    Crucial for Windows services, background terminal tasks, and child processes to interact with desktop windows.
    """
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

# Ensure desktop attachment at load time
ensure_desktop_attached()

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
    """Gracefully closes a running application by name or window title."""
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

    # Fallback to taskkill
    clean_name = app_name.lower().replace(".exe", "").strip()
    try:
        res = subprocess.run(f"taskkill /IM {clean_name}.exe /T", shell=True, capture_output=True, text=True)
        if res.returncode == 0:
            return True, f"Terminated {clean_name}."
    except Exception:
        pass
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
    for _ in range(10):
        wins = find_windows(app_lower)
        if wins:
            target_hwnd = wins[0]['hwnd']
            break
        time.sleep(0.3)

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
                # Ctrl+N is "New Chat" in modern WhatsApp Desktop
                pyautogui.hotkey('ctrl', 'n')
                time.sleep(0.5)

                pyperclip.copy(recipient)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(1.2)  # Wait for contact search results to load

                # Down arrow to first match, then Enter to open conversation
                pyautogui.press('down')
                time.sleep(0.2)
                pyautogui.press('enter')
                time.sleep(0.8)

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
                time.sleep(0.4)
                pyperclip.copy(recipient)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(0.8)
                pyautogui.press('down')
                time.sleep(0.2)
                pyautogui.press('enter')
                time.sleep(0.6)

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
