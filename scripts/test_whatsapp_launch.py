import os
import time
import win32gui
import win32process
import psutil

print("All processes with whatsapp in name or exe:")
for p in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        name = p.info['name'] or ''
        exe = p.info['exe'] or ''
        if 'whatsapp' in name.lower() or 'whatsapp' in exe.lower():
            print(f"PID {p.info['pid']}: Name={name}, Exe={exe}")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print("\nChecking all visible windows:")
def enum_cb(hwnd, _):
    try:
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            pname = ""
            try:
                pname = psutil.Process(pid).name()
            except:
                pname = "unknown"
            if any(k in title.lower() or k in pname.lower() for k in ['whatsapp', 'framehost', 'telegram', 'code']):
                print(f"HWND {hwnd}: Title='{title}', Proc={pname}, PID={pid}")
    except Exception as e:
        pass
    return True

win32gui.EnumWindows(enum_cb, None)
