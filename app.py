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
from agent_tools import build_default_registry
from chat_cli import load_mission
from chat_core import AgentCore, ProviderError, TurnCancelled, build_system_prompt
from voice import VoiceEngine, SentenceSpeechStreamer

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

        # Window controls are handled by pywebview, so the chat panel can be
        # minimized reliably without depending on frameless-window behavior.
        if 'minimize' in message:
            if self._app.window:
                self._app.window.minimize()

        elif 'close' in message:
            if self._app.window:
                self._app.window.destroy()

        # 1. User typed an ask and submitted
        elif 'send' in message:
            text = str(message['send']).strip()
            if text:
                self._app.submit_user_turn('user_typed_ask', self._app.handle_user_ask, text, caller_id='desktop_user')

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

        # 8. Heartbeat notice actions
        elif 'dismiss_notice' in message:
            notice_id = str(message['dismiss_notice'])
            if hasattr(self._app, 'heartbeat') and self._app.heartbeat:
                self._app.heartbeat.dismiss_notice(notice_id)

        elif 'get_inbox' in message:
            if hasattr(self._app, 'heartbeat') and self._app.heartbeat:
                notices = [n.to_dict() for n in self._app.heartbeat.load_inbox()]
                self._app.eval_js(f"window.ui.inbox({json.dumps(notices)})")

class HomieApp:
    def __init__(self):
        self.prefs = homie.get_prefs()
        assistant_name = os.environ.get('HOMIE_NAME') or self.prefs.get('assistantName') or 'Homie'
        import durable_memory
        memory_store = durable_memory.get_default_memory_store()
        self.agent_core = AgentCore(
            build_system_prompt(str(assistant_name), load_mission(), facts=memory_store.list_facts()),
            self.prefs,
            tool_registry=build_default_registry(),
            memory_store=memory_store,
        )
        self.window = None
        self.voice = VoiceEngine(
            model_size=self.prefs.get('whisperModel', 'tiny'),
            language=self.prefs.get('whisperLanguage', 'en')
        )
        self.api = HomieApi(self)
        self.tasks = task_manager.get_task_manager()
        import heartbeat_service
        self.heartbeat = heartbeat_service.get_default_heartbeat_service()
        self.heartbeat.on_surface_callback = self._handle_heartbeat_notice
        self._ask_tasks = []
        self._ask_tasks_lock = threading.Lock()
        self._speech_stream_active = threading.Event()
        self.is_recording = False
        self.paused = False
        self.held_keys = set()
        self.hotkey_listener = None
        self._ll_hook = None
        self._hook_proc = None
        self._running_hotkey = True
        self._physical_ctrl_down = False
        self._physical_alt_down = False
        self.tray = None
        self.telegram = None

    def _handle_heartbeat_notice(self, notice):
        """Surfaces proactive alerts in UI or timeline."""
        try:
            assistant_timeline.record_timeline_event(
                category="heartbeat",
                title=notice.title,
                summary=notice.message,
                metadata={"notice_id": notice.notice_id, "severity": notice.severity}
            )
            msg = f"[{notice.title}] {notice.message}"
            self.eval_js(f"window.ui.notice({json.dumps(msg)})")
        except Exception as e:
            print(f"[Heartbeat] Error surfacing notice: {e}")

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
        """Load the Windows chat panel with a pywebview-compatible bridge."""
        ui_path = os.path.join(BASE_DIR, 'ui', 'chat.html')
        with open(ui_path, 'r', encoding='utf-8') as f:
            return f.read()

    def start_listening(self):
        """Initiates voice recording on hotkey press."""
        if self.is_recording or self.paused:
            return
        if self.is_processing:
            # Barge-in is accepted only after assistant audio has actually started.
            if not self._speech_stream_active.is_set():
                return
            self.cancel_active_user_turns()
        self._speech_stream_active.clear()

        self.is_recording = True
        self.show_window()
        self.eval_js("window.ui.listen()")

        def on_level(lvl):
            if self.is_recording:
                self.eval_js(f"window.ui.level({lvl:.3f})")

        if self.voice.start_recording(level_callback=on_level) is False:
            self.is_recording = False
            self.eval_js("window.ui.stopped('Microphone unavailable')")

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
        self.submit_user_turn('voice_audio_transcription', self._process_audio, audio_data)

    def toggle_listening(self):
        """Toggles recording for press-to-talk mode."""
        if self.is_recording:
            self.stop_listening()
        else:
            self.start_listening()

    def submit_user_turn(self, name, function, *args, **kwargs):
        """Track user-initiated turns so barge-in cancels only those turns."""
        with self._ask_tasks_lock:
            self._ask_tasks = [task for task in self._ask_tasks if task.status.value in ('PENDING', 'RUNNING')]
            task = self.tasks.submit_task(name, function, *args, **kwargs)
            self._ask_tasks.append(task)
            return task

    def cancel_active_user_turns(self):
        with self._ask_tasks_lock:
            active = [task for task in self._ask_tasks if task.status.value in ('PENDING', 'RUNNING')]
        for task in active:
            task.cancel()
        self._speech_stream_active.clear()

    def _process_audio(self, audio_data, cancel_event=None):
        self.is_processing = True
        try:
            if cancel_event and cancel_event.is_set():
                return
            # Transcribe speech
            text = self.voice.transcribe(audio_data)
            if cancel_event and cancel_event.is_set():
                return
            if not text:
                # No speech heard; open typing composer
                self.eval_js("window.ui.compose(true)")
                return

            self.handle_user_ask(text, caller_id='desktop_voice', cancel_event=cancel_event)
        finally:
            self.is_processing = False

    def handle_user_ask(self, text, caller_id='desktop_voice', cancel_event=None):
        """Handles an ask either from voice or typing."""
        self.is_processing = True
        speak = caller_id == 'desktop_voice' or bool(self.prefs.get('speak', False))
        self._speech_stream_active.clear()
        speech = SentenceSpeechStreamer(
            enabled=speak,
            on_start=self._speech_stream_active.set,
        )
        try:
            if cancel_event and cancel_event.is_set():
                return
            self.eval_js(f"window.ui.words({json.dumps(text)})")
            self.eval_js("window.ui.think()")
            self.prefs = homie.get_prefs()
            self.agent_core.prefs = self.prefs

            def on_delta(delta):
                if cancel_event and cancel_event.is_set():
                    return
                speech.feed(delta)
                self.eval_js(f"window.ui.line({json.dumps('… ' + delta)})")

            result = self.agent_core.turn(
                text,
                on_delta,
                caller_id=caller_id,
                quick_action_handler=homie.try_fast_command,
                cancel_event=cancel_event,
            )
            if cancel_event and cancel_event.is_set():
                speech.cancel()
                return
            speech.finish()
            self.eval_js(f"window.ui.line({json.dumps('✓ ' + result)})")
        except TurnCancelled:
            speech.cancel()
            return
        except ProviderError as e:
            speech.cancel()
            self.eval_js(f"window.ui.line({json.dumps('· ' + str(e))})")
        except Exception as e:
            speech.cancel()
            self.eval_js(f"window.ui.line({json.dumps('· Error: ' + str(e))})")
        finally:
            if not self.is_recording:
                self._speech_stream_active.clear()
            self.is_processing = False

    def show_window(self):
        """Restores the chat window when a hotkey arrives while it is minimized."""
        if self.window:
            try:
                self.window.restore()
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

    def _trigger_pairing_async(self):
        try:
            import phone_approval_portal
            sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=120.0)
            if sess_id:
                self.eval_js(f"window.ui.notice('Pairing ceremony active: {sess_id}')")
        except Exception as e:
            logger.error("Error triggering async pairing: %s", e)

    def reset_physical_modifiers(self):
        """Resets tracked physical modifier keys upon focus loss (WM_KILLFOCUS) or window deactivation."""
        self._physical_ctrl_down = False
        self._physical_alt_down = False

    def handle_keyboard_event(self, nCode: int, wParam: int, lParam: int) -> int:
        """Low-level keyboard hook callback.
        Guarantees physical console presence for pairing hotkey (Ctrl + Alt + P).
        Rejects all synthetic/injected keystrokes (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED).
        Dispatches pairing asynchronously to worker thread to prevent LowLevelHooksTimeout.
        Clears physical modifiers on focus loss (WM_KILLFOCUS) and key-up.
        """
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        WM_KILLFOCUS = 0x0008
        WM_KEYDOWN = 0x0100
        WM_KEYUP = 0x0101
        WM_SYSKEYDOWN = 0x0104
        WM_SYSKEYUP = 0x0105
        LLKHF_INJECTED = 0x00000001
        LLKHF_LOWER_IL_INJECTED = 0x00000002

        if wParam == WM_KILLFOCUS:
            self.reset_physical_modifiers()
            return 0

        if nCode >= 0 and lParam:
            class KBDLLHOOKSTRUCT(ctypes.Structure):
                _fields_ = [
                    ("vkCode", wintypes.DWORD),
                    ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD),
                    ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_ulong),
                ]
            kb = KBDLLHOOKSTRUCT.from_address(lParam)
            is_injected = bool(kb.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED))
            if is_injected:
                # Reject any synthesized input attempting to trigger pairing ceremony
                if self._ll_hook:
                    return user32.CallNextHookEx(self._ll_hook, nCode, wParam, lParam)
                return 0

            # Track physical key states exclusively through the physical low-level hook
            vk = kb.vkCode
            if wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                if vk in (0x11, 0xA2, 0xA3):  # VK_CONTROL, VK_LCONTROL, VK_RCONTROL
                    self._physical_ctrl_down = True
                elif vk in (0x12, 0xA4, 0xA5):  # VK_MENU, VK_LMENU, VK_RMENU
                    self._physical_alt_down = True
                elif vk == 0x50:  # VK_P
                    if getattr(self, "_physical_ctrl_down", False) and getattr(self, "_physical_alt_down", False):
                        # Asynchronous dispatch to background thread (avoids blocking hook thread)
                        threading.Thread(target=self._trigger_pairing_async, daemon=True).start()
            elif wParam in (WM_KEYUP, WM_SYSKEYUP):
                if vk in (0x11, 0xA2, 0xA3):
                    self._physical_ctrl_down = False
                elif vk in (0x12, 0xA4, 0xA5):
                    self._physical_alt_down = False

        if self._ll_hook:
            return user32.CallNextHookEx(self._ll_hook, nCode, wParam, lParam)
        return 0

    def start_hotkey_listener(self):
        """Listens for the hold-to-talk shortcut globally across Windows using native GetAsyncKeyState,
        and installs a low-level keyboard hook (WH_KEYBOARD_LL) to enforce physical presence for pairing.
        """
        import ctypes
        from ctypes import wintypes
        VK_CONTROL = 0x11
        VK_SHIFT = 0x10
        VK_MENU = 0x12   # Alt key
        VK_SPACE = 0x20  # Space bar
        VK_ESCAPE = 0x1B # Esc key

        def is_down(vk):
            return bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)

        # 1. Dedicated low-level hook thread with message pump for physical-only Ctrl+Alt+P
        def hook_worker():
            try:
                user32 = ctypes.windll.user32
                HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
                self._hook_proc = HOOKPROC(self.handle_keyboard_event)
                self._ll_hook = user32.SetWindowsHookExW(13, self._hook_proc, None, 0)
                msg = wintypes.MSG()
                while self._running_hotkey:
                    b_ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                    if b_ret in (0, -1):
                        break
                    if msg.message in (0x0008, 0x001C):  # WM_KILLFOCUS, WM_ACTIVATEAPP
                        self.reset_physical_modifiers()
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
            except Exception:
                pass

        t_hook = threading.Thread(target=hook_worker, daemon=True)
        t_hook.start()

        def hotkey_worker():
            was_holding = False
            while True:
                time.sleep(0.02)  # 50Hz poll (uses <0.01% CPU)
                try:
                    ctrl = is_down(VK_CONTROL)
                    space = is_down(VK_SPACE)
                    alt = is_down(VK_MENU)
                    if self._physical_ctrl_down and not ctrl:
                        self._physical_ctrl_down = False
                    if self._physical_alt_down and not alt:
                        self._physical_alt_down = False
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

        # 0b. Start proactive heartbeat scheduled checks loop
        if hasattr(self, 'heartbeat') and self.heartbeat:
            self.heartbeat.start()

        # 1. Start global hotkey listener
        self.start_hotkey_listener()

        # 2. Start system tray icon
        self.start_tray_icon()

        # 3. Start Telegram remote control bridge (if token configured)
        self.start_telegram_bridge()

        # 4. Create a compact, normal Windows chat window. A native frame keeps
        # minimize/restore behavior predictable; the chat toolbar has its own
        # minimize button as well.
        html_content = self.get_ui_html()
        monitors = windows_tools.get_monitors()
        primary = monitors[0] if monitors else {'x': 0, 'y': 0}
        window_width = min(380, max(340, primary.get('width', 380) - 32))
        window_height = min(500, max(420, primary.get('height', 500) - 48))
        win_x = primary.get('x', 0) + max(16, primary.get('width', window_width) - window_width - 20)
        win_y = primary.get('y', 0) + 20

        self.window = webview.create_window(
            title='Homie',
            html=html_content,
            js_api=self.api,
            width=window_width,
            height=window_height,
            x=win_x,
            y=win_y,
            min_size=(340, 420),
            resizable=True,
            frameless=False,
            on_top=False,
            transparent=False,
            easy_drag=False
        )

        def on_loaded():
            self.eval_js("window.ui.status('Homie Ready', false)")
            self.eval_js("window.ui.mode(true)")
            if hasattr(self, 'heartbeat') and self.heartbeat:
                pending = self.heartbeat.get_pending_held_notices()
                if pending:
                    self.heartbeat.mark_notices_delivered()
                    for p in pending:
                        self.eval_js(f"window.ui.notice({json.dumps('[' + p.title + '] ' + p.message)})")

        self.window.events.loaded += on_loaded

        # Start webview event loop (runs on main thread)
        webview.start(debug=False)

def main():
    app = HomieApp()
    app.run()

if __name__ == '__main__':
    main()
