import ctypes
from ctypes import wintypes
import psutil

all_windows = []
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

def enum_cb(hwnd, lparam):
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    if length > 0:
        buff = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
        title = buff.value
        all_windows.append((hwnd, title))
    return 1

cb = WNDENUMPROC(enum_cb)
ctypes.windll.user32.EnumWindows(cb, 0)
print(f"Total windows with text: {len(all_windows)}")
for h, t in all_windows[:30]:
    print(f"HWND {h}: {t}")
