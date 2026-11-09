#!/usr/bin/env python3
"""Homie Desktop App: The floating hold-to-talk voice assistant for Windows.
Hosts the glowing translucent card UI, runs the global hotkey listener,
records your voice, and bridges to Homie's automation & Claude AI brain.
"""
import os
import sys
import json
import time
import threading
import pyperclip
import pyautogui
import webview
from pynput import keyboard
from PIL import Image

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie
import windows_tools
import task_manager
import assistant_timeline
from voice import VoiceEngine

class HomieApi:
    """JS Bridge exposed to the webview via pywebview.api."""
    def __init__(self, app):
        self._app = app

    def __dir__(self):
        return ['post']

    def post(self, message):
        """Receives events and actions dispatched from the UI."""
        if not isinstance(message, dict):
            return

        # 1. User typed an ask and submitted
        if 'send' in message:
            text = str(message['send']).strip()
            if text:
                self._app.tasks.submit_task('user_typed_ask', self._app.handle_user_ask, text, caller_id='desktop_user')

        # 2. Copy answer
        elif 'copy' in message:
            pyperclip.copy(str(message['copy']))
            self._app.eval_js("window.ui.notice('Copied to clipboard')")

        # 3. Insert / Replace at cursor
        elif 'replace' in message:
            time.sleep(0.1)
            pyautogui.hotkey('ctrl', 'v')

        # 4. Manual mic button click
        elif 'mic' in message:
            self._app.toggle_listening()

        # 5. Safe mode switch
        elif 'safe' in message:
            homie.save_pref('safe', bool(message['safe']))
            self._app.eval_js("window.ui.mode(true)")

        # 6. User clicked tip / support
        elif 'kofi' in message:
            import webbrowser
            webbrowser.open("https://github.com/SaarthurR/atticus-mac")

        # 7. Resume app
        elif 'resume' in message:
            self._app.paused = False
            self._app.eval_js("window.ui.paused(false)")

class HomieApp:
    def __init__(self):
        self.prefs = homie.get_prefs()
        self.window = None
        self.voice = VoiceEngine(
            model_size=self.prefs.get('whisperModel', 'tiny'),
            language=self.prefs.get('whisperLanguage', 'en')
        )
        self.api = HomieApi(self)
        self.tasks = task_manager.get_task_manager()
        self.is_recording = False
        self.paused = False
        self.held_keys = set()
        self.hotkey_listener = None
        self.tray = None
        self.telegram = None

    def start_telegram_bridge(self):
        """Starts the Telegram bridge if a bot token is available."""
        try:
            # Terminate any standalone telegram_bridge process to prevent 409 Conflict
            import subprocess
            try:
                my_pid = os.getpid()
                subprocess.run(
                    f'powershell -Command "Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like \'*telegram_bridge.py*\' -and $_.ProcessId -ne {my_pid} }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"',
                    shell=True, timeout=4
                )
            except Exception:
                pass

            from telegram_bridge import TelegramBridge
            self.telegram = TelegramBridge()
            if self.telegram.token:
                self.telegram.start()
                print("[App] Telegram remote control bridge active.")
        except Exception as e:
            print(f"[App] Telegram bridge error: {e}")

    def eval_js(self, script):
        """Thread-safe evaluation of JavaScript in the overlay window."""
        if self.window:
            try:
                self.window.evaluate_js(script)
            except Exception:
                pass

    def get_ui_html(self):
        """Loads ui.html with orbs.js inlined at /*ORBS*/."""
        ui_path = os.path.join(BASE_DIR, 'ui', 'ui.html')
        orbs_path = os.path.join(BASE_DIR, 'ui', 'orbs.js')
        with open(ui_path, 'r', encoding='utf-8') as f:
            html = f.read()
        with open(orbs_path, 'r', encoding='utf-8') as f:
            orbs = f.read()
        return html.replace('/*ORBS*/', orbs)

    def start_listening(self):
        """Initiates voice recording on hotkey press."""
        if self.is_recording or self.is_processing or self.paused:
            return

        self.is_recording = True
        self.show_window()
        self.eval_js("window.ui.listen()")

        def on_level(lvl):
            if self.is_recording:
                self.eval_js(f"window.ui.level({lvl:.3f})")

        self.voice.start_recording(level_callback=on_level)

    @property
    def is_processing(self) -> bool:
        return self.tasks.is_busy()

    @is_processing.setter
    def is_processing(self, val: bool):
        pass

    def stop_listening(self):
        """Stops voice recording and begins processing on hotkey release."""
        if not self.is_recording:
            return

        self.is_recording = False
        self.eval_js("window.ui.think()")

        # Stop audio capture
        audio_data = self.voice.stop_recording()

        # Process via durable TaskManager with bounded workers and cancellation
        self.tasks.submit_task('voice_audio_transcription', self._process_audio, audio_data)

    def toggle_listening(self):
        """Toggles recording for press-to-talk mode."""
        if self.is_recording:
            self.stop_listening()
        else:
            self.start_listening()

    def _process_audio(self, audio_data):
        self.is_processing = True
        try:
            # Transcribe speech
            text = self.voice.transcribe(audio_data)
            if not text:
                # No speech heard; open typing composer
                self.eval_js("window.ui.compose(true)")
                return

            self.handle_user_ask(text)
        finally:
            self.is_processing = False

    def handle_user_ask(self, text, caller_id='desktop_voice'):
        """Handles an ask either from voice or typing."""
        self.is_processing = True
        try:
            self.eval_js(f"window.ui.words({json.dumps(text)})")
            self.eval_js("window.ui.think()")

            # 1. Try instant command (<50ms, $0)
            handled, fast_msg = homie.try_fast_command(text, caller_id=caller_id)
            if handled:
                time.sleep(0.05)
                self.eval_js(f"window.ui.line({json.dumps('✓ ' + fast_msg)})")
                return

            # 2. Invoke AI brain (Google AI Studio, NVIDIA NIM, Groq, Ollama, Claude)
            def on_step(line):
                self.eval_js(f"window.ui.line({json.dumps(line)})")

            result = homie.run_ai(text, step_callback=on_step)
            # Ensure final response is displayed
            if result and not result.startswith(('·', '▸', '✓')):
                self.eval_js(f"window.ui.line({json.dumps('✓ ' + result)})")

        except Exception as e:
            self.eval_js(f"window.ui.line({json.dumps('· Error: ' + str(e))})")
        finally:
            self.is_processing = False

    def show_window(self):
        """Ensures the floating overlay window is visible and on top."""
        if self.window:
            try:
                self.window.show()
            except Exception:
                pass

    def hide_window(self):
        """Hides the floating overlay window."""
        if self.window:
            try:
                self.window.hide()
            except Exception:
                pass

    def start_hotkey_listener(self):
        """Listens for the hold-to-talk shortcut globally across Windows using native GetAsyncKeyState."""
        import ctypes
        VK_CONTROL = 0x11
        VK_SHIFT = 0x10
        VK_MENU = 0x12   # Alt key
        VK_SPACE = 0x20  # Space bar
        VK_ESCAPE = 0x1B # Esc key

        def is_down(vk):
            return bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)

        def hotkey_worker():
            was_holding = False
            while True:
                time.sleep(0.02)  # 50Hz poll (uses <0.01% CPU)
                try:
                    ctrl = is_down(VK_CONTROL)
                    space = is_down(VK_SPACE)
                    alt = is_down(VK_MENU)
                    shift = is_down(VK_SHIFT)
                    esc = is_down(VK_ESCAPE)

                    if esc:
                        if self.is_recording:
                            self.is_recording = False
                            self.voice.stop_recording()
                            self.eval_js("window.ui.stopped('Cancelled')")
                            time.sleep(0.3)
                        continue

                    # Trigger hold-to-talk on Ctrl+Alt+Space OR Ctrl+Shift+Space
                    is_holding = ctrl and space and (alt or shift)

                    if is_holding and not was_holding:
                        was_holding = True
                        self.start_listening()
                    elif not is_holding and was_holding:
                        was_holding = False
                        self.stop_listening()

                    # Quick Note trigger: Ctrl + Alt + N
                    if ctrl and alt and is_down(0x4E): # VK_N
                        import quick_notes
                        clip = windows_tools.get_clipboard_text()
                        if clip:
                            nid = quick_notes.save_quick_note(clip, is_pinned=True)
                            self.eval_js(f"window.ui.notice('Pinned Note #{nid} from Clipboard')")
                        else:
                            self.show_window()
                            self.eval_js("window.ui.notice('Quick Note scratchpad active')")
                        time.sleep(0.4)

                    # Phone Pairing Ceremony trigger: Ctrl + Alt + P (physical console presence only)
                    if ctrl and alt and is_down(0x50): # VK_P
                        import phone_approval_portal
                        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=120.0)
                        if sess_id:
                            self.eval_js(f"window.ui.notice('Pairing ceremony active: {sess_id[:8]}')")
                        time.sleep(0.4)

                except Exception:
                    pass

        t = threading.Thread(target=hotkey_worker, daemon=True)
        t.start()

    def start_tray_icon(self):
        """Creates the system tray icon and unified HUD menu."""
        try:
            import tray_hud
            icon_path = os.path.join(BASE_DIR, 'ui', 'AppIcon.png')
            self.tray = tray_hud.create_tray_hud(app=self, icon_path=icon_path)
            threading.Thread(target=self.tray.run, daemon=True).start()
        except Exception as e:
            print(f"[Tray] Tray icon error: {e}")

    def run(self):
        """Launches Homie's GUI and services."""
        # 0. Start unified Assistant Timeline monitor & retention pruner
        assistant_timeline.start_timeline_monitor()

        # 1. Start global hotkey listener
        self.start_hotkey_listener()

        # 2. Start system tray icon
        self.start_tray_icon()

        # 3. Start Telegram remote control bridge (if token configured)
        self.start_telegram_bridge()

        # 4. Create PyWebView transparent floating overlay
        html_content = self.get_ui_html()
        monitors = windows_tools.get_monitors()
        primary = monitors[0] if monitors else {'x': 0, 'y': 0}
        win_x = primary.get('x', 0) + 24
        win_y = primary.get('y', 0) + 24

        self.window = webview.create_window(
            title='Homie',
            html=html_content,
            js_api=self.api,
            width=500,
            height=430,
            x=win_x,
            y=win_y,
            frameless=True,
            on_top=True,
            transparent=True,
            easy_drag=True
        )

        def on_loaded():
            self.eval_js("window.ui.status('Homie Ready', false)")
            self.eval_js("window.ui.mode(true)")

        self.window.events.loaded += on_loaded

        # Start webview event loop (runs on main thread)
        webview.start(debug=False)

def main():
    app = HomieApp()
    app.run()

if __name__ == '__main__':
    main()
