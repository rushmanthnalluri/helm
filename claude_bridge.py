"""Homie Claude Chrome Bridge & Autonomous Feedback Loop.
Connects Homie directly to the user's active Claude AI web session in Chrome:
- Automatically detects and focuses the Claude tab in Google Chrome
- Sends audit results, progress reports, and architectural queries directly to Claude
- Captures Claude's feedback, insights, and next-step recommendations
- Drives the autonomous improvement loop: Claude -> Improve -> Update Claude -> Repeat
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import pyautogui
import pyperclip
import mss

logger = logging.getLogger("homie.claude_bridge")
pyautogui.FAILSAFE = False

LOG_PATH = Path(BASE_DIR) / "claude_loop_log.jsonl"

def find_claude_window():
    """Finds the HWND and geometry of the active Claude Chrome window."""
    windows_tools.ensure_desktop_attached()
    wins = windows_tools.find_windows("Claude")
    if not wins:
        # Fallback to any chrome window with claude in title
        import win32gui
        results = []
        def cb(h, _):
            if win32gui.IsWindowVisible(h):
                t = win32gui.GetWindowText(h)
                if "claude" in t.lower() and "chrome" in t.lower():
                    results.append({"hwnd": h, "title": t, "rect": win32gui.GetWindowRect(h)})
        win32gui.EnumWindows(cb, None)
        if results:
            return results[0]
        return None
    return wins[0]

def send_message_to_claude(prompt_text, wait_for_reply_sec=12):
    """Brings Claude in Chrome forward, enters the prompt into the chat box, and sends it."""
    win = find_claude_window()
    if not win:
        return False, "Could not find an open Claude AI window in Google Chrome."

    hwnd = win["hwnd"]
    rect = win["rect"]
    logger.info("Found Claude window: HWND=%s Rect=%s", hwnd, rect)

    # 1. Bring window forward and restore if minimized
    windows_tools.force_foreground_window(hwnd)
    time.sleep(0.5)

    # 2. Refresh rect after foregrounding
    import win32gui
    rect = win32gui.GetWindowRect(hwnd)
    left, top, right, bottom = rect
    width = right - left
    height = bottom - top

    # 3. Calculate target click coordinates for Claude input box
    # Claude's input box in active conversation is located near the bottom of the window
    click_x = left + int(width * 0.55)
    click_y = bottom - 110

    logger.info("Clicking Claude input prompt at (%d, %d)", click_x, click_y)
    pyautogui.click(click_x, click_y)
    time.sleep(0.3)

    # 4. Copy text to clipboard and paste
    pyperclip.copy(prompt_text)
    time.sleep(0.2)
    pyautogui.hotkey("ctrl", "v")
    time.sleep(0.3)

    # 5. Press Enter to submit prompt
    pyautogui.press("enter")
    logger.info("Prompt submitted to Claude. Waiting %d seconds for response...", wait_for_reply_sec)
    
    # 6. Log submission
    event = {
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "prompt": prompt_text[:300] + ("..." if len(prompt_text) > 300 else ""),
        "status": "sent"
    }
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    # 7. Wait and capture response screenshot
    if wait_for_reply_sec > 0:
        time.sleep(wait_for_reply_sec)
        shot_path = Path(BASE_DIR) / "claude_latest_response.png"
        try:
            with mss.mss() as sct:
                bbox = {"left": max(0, left), "top": max(0, top), "width": width, "height": height}
                shot = sct.grab(bbox)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                img.save(str(shot_path))
                return True, f"Prompt sent successfully to Claude. Screenshot saved to {shot_path.name}"
        except Exception as e:
            return True, f"Prompt sent successfully (screenshot capture error: {e})"

    return True, "Prompt sent successfully to Claude."

def read_claude_feedback_vision():
    """Uses multimodal vision to transcribe Claude's latest response from the screen capture."""
    shot_path = Path(BASE_DIR) / "claude_latest_response.png"
    if not shot_path.exists():
        return "No Claude response screenshot available."

    try:
        import ai_engine
        import homie
        prefs = homie.get_prefs()
        key = prefs.get("geminiKey")
        res = ai_engine.run_gemini_vision(
            "Transcribe or summarize the latest AI response message visible in this Claude AI window. "
            "Focus specifically on the actionable suggestions and feedback given by Claude.",
            str(shot_path),
            api_key=key
        )
        return res
    except Exception as e:
        return f"Could not read Claude response via vision: {e}"

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--post":
        msg = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "Status check from Homie assistant."
        ok, res = send_message_to_claude(msg)
        print("Result:", ok, res)
    else:
        win = find_claude_window()
        print("Claude Window Status:", win if win else "Not open or detected")
