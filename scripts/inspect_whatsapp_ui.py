import sys
import time
sys.path.insert(0, r'd:\helm')

import uiautomation as auto
import windows_tools

wins = windows_tools.find_windows('whatsapp')
if not wins:
    windows_tools.launch_app('whatsapp')
    time.sleep(2.0)
    wins = windows_tools.find_windows('whatsapp')

print("Wins:", wins)
if wins:
    hwnd = wins[0]['hwnd']
    windows_tools.force_foreground_window(hwnd)
    time.sleep(0.5)
    ctrl = auto.ControlFromHandle(hwnd)
    print("Found WhatsApp HWND:", hwnd, "Control:", ctrl)
    
    # Walk tree
    nodes = []
    def walk(c, depth=0):
        if depth > 6:
            return
        for child in c.GetChildren():
            name = child.Name or ''
            aid = child.AutomationId or ''
            ctype = child.ControlTypeName or ''
            rect = child.BoundingRectangle
            if name or aid or ctype in ('EditControl', 'ButtonControl', 'ListItemControl'):
                nodes.append((depth, ctype, name, aid, rect))
            walk(child, depth + 1)
            
    walk(ctrl)
    print(f"Total interesting elements found: {len(nodes)}")
    for d, ct, nm, aid, r in nodes[:40]:
        print(f"{'  '*d}[{ct}] Name='{nm}' ID='{aid}' Rect={r}")
