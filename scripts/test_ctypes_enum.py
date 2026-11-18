import ctypes
from ctypes import wintypes
import psutil

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_long, wintypes.HWND, wintypes.LPARAM)

results = []

def cb(hwnd, lparam):
    ctypes.windll.kernel32.SetLastError(0)
    if not ctypes.windll.user32.IsWindowVisible(hwnd):
        return 1
    
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    title = ""
    if length > 0:
        buf = ctypes.create_unicode_buffer(length + 2)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
    
    rect = wintypes.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    if w < 100 or h < 100:
        return 1
        
    pid = wintypes.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    proc_name = ""
    try:
        proc_name = psutil.Process(pid.value).name()
    except:
        pass
        
    results.append({
        'hwnd': hwnd,
        'title': title,
        'proc_name': proc_name,
        'pid': pid.value,
        'rect': (rect.left, rect.top, rect.right, rect.bottom)
    })
    return 1

proc = EnumWindowsProc(cb)
ctypes.windll.user32.EnumWindows(proc, 0)
print(f"Total windows found via ctypes: {len(results)}")
for r in results:
    if 'whatsapp' in r['title'].lower() or 'whatsapp' in r['proc_name'].lower():
        print("WHATSAPP:", r)
    elif 'telegram' in r['title'].lower() or 'telegram' in r['proc_name'].lower():
        print("TELEGRAM:", r)
