import win32gui
import win32process
import win32con

hwnd = 461464
print("IsWindow(461464):", win32gui.IsWindow(hwnd))
if win32gui.IsWindow(hwnd):
    print("IsWindowVisible:", win32gui.IsWindowVisible(hwnd))
    print("WindowText:", win32gui.GetWindowText(hwnd))
    print("ClassName:", win32gui.GetClassName(hwnd))
    style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
    print("Is Minimized:", bool(style & win32con.WS_MINIMIZE))
    
    # Try restoring it
    print("Restoring...")
    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
    win32gui.SetForegroundWindow(hwnd)
    print("Now visible:", win32gui.IsWindowVisible(hwnd))
