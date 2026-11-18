import win32gui
import win32process
import psutil

for hwnd in range(1, 0x1000000): # Wait, EnumWindows is faster!
    pass

hwnds = []
def enum_cb(h, _):
    try:
        _, pid = win32process.GetWindowThreadProcessId(h)
        if pid == 5072:
            hwnds.append(h)
    except:
        pass
    return True

win32gui.EnumWindows(enum_cb, None)
print(f"HWNDs belonging to PID 5072: {hwnds}")
for h in hwnds:
    print(f"HWND: {h}, Text: '{win32gui.GetWindowText(h)}', Class: '{win32gui.GetClassName(h)}', Visible: {win32gui.IsWindowVisible(h)}, Rect: {win32gui.GetWindowRect(h)}")
