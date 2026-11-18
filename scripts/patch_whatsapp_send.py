with open('windows_tools.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''            if recipient:
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
                pyautogui.press('enter')'''

replacement = '''            if recipient:
                # Ctrl+F / Ctrl+E to search chats in WhatsApp Desktop
                pyautogui.hotkey('ctrl', 'f')
                time.sleep(0.3)
                pyautogui.hotkey('ctrl', 'a')
                time.sleep(0.1)
                pyautogui.press('backspace')
                time.sleep(0.1)

                pyperclip.copy(recipient)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(1.2)  # Wait for contact search results to load

                # In WhatsApp Desktop UWP/WinUI: Pressing Enter selects the top matched contact directly.
                # If Enter alone doesn't focus, Down then Enter selects the first list item.
                pyautogui.press('enter')
                time.sleep(0.5)
                # Ensure the message input box is focused
                pyautogui.press('tab')
                time.sleep(0.3)

            if target_hwnd:
                force_foreground_window(target_hwnd)
                time.sleep(0.3)

            if message:
                pyperclip.copy(message)
                pyautogui.hotkey('ctrl', 'v')
                time.sleep(0.4)
                pyautogui.press('enter')
                time.sleep(0.3)'''

if target in text:
    text = text.replace(target, replacement)
    with open('windows_tools.py', 'w', encoding='utf-8', newline='') as f:
        f.write(text)
    print("Successfully updated WhatsApp automation in windows_tools.py!")
else:
    print("Target not found in windows_tools.py!")
