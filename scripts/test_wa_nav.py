import sys
sys.path.insert(0, r'd:\helm')

import uiautomation as auto
import windows_tools

wins = windows_tools.find_windows('whatsapp')
if wins:
    hwnd = wins[0]['hwnd']
    ctrl = auto.ControlFromHandle(hwnd)
    print("Found WhatsApp HWND:", hwnd)
    
    # Find all edit controls
    edits = ctrl.GetChildren()
    print("Direct children:", len(edits))
    
    all_ctrls = []
    def find_ctrls(c, depth=0):
        if depth > 4:
            return
        for child in c.GetChildren():
            all_ctrls.append((depth, child.ControlTypeName, child.Name, child.AutomationId))
            find_ctrls(child, depth + 1)
            
    find_ctrls(ctrl)
    print(f"Total controls: {len(all_ctrls)}")
    for d, ctype, name, aid in all_ctrls[:30]:
        print(f"{'  '*d}[{ctype}] Name='{name}' ID='{aid}'")
