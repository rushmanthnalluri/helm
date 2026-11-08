"""Telegram Remote Bridge for Homie.
Enables calling/messaging your Windows PC from Telegram on your phone for 100% free.
Supports voice notes (walkie-talkie style), text prompts, live screen captures,
and Windows PC automation controls.
"""
import os
import sys
import time
import json
import tempfile
import threading
import requests

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie
import windows_tools

TELEGRAM_API_BASE = "https://api.telegram.org"
_SHARED_WHISPER = None

def decode_audio_file(file_path, sample_rate=16000):
    """Decodes OGG/Opus or any audio format to 16kHz float32 numpy array using PyAV."""
    import av
    import numpy as np
    try:
        container = av.open(file_path, mode='r')
        resampler = av.AudioResampler(format='fltp', layout='mono', rate=sample_rate)
        frames = []
        for frame in container.decode(audio=0):
            for r_frame in resampler.resample(frame):
                frames.append(r_frame.to_ndarray().flatten())
        container.close()
        if frames:
            return np.concatenate(frames).astype(np.float32)
    except Exception as e:
        print(f"[Telegram] Audio decode error: {e}", flush=True)
    return None

def get_whisper_model():
    global _SHARED_WHISPER
    if _SHARED_WHISPER is None:
        from faster_whisper import WhisperModel
        whisper_dir = os.path.join(homie.CONFIG_DIR, 'whisper')
        prefs = homie.get_prefs()
        model_name = prefs.get('whisperModel', 'small')
        # Load high-accuracy model with fallback to base/tiny
        for m in (model_name, "small", "base", "tiny"):
            try:
                _SHARED_WHISPER = WhisperModel(m, device="cpu", compute_type="int8", download_root=whisper_dir)
                print(f"[Telegram] Loaded Whisper model: {m}", flush=True)
                break
            except Exception as e:
                print(f"[Telegram] Failed to load Whisper {m}: {e}", flush=True)
    return _SHARED_WHISPER

class TelegramBridge:
    def __init__(self, token=None, allowed_users=None):
        self.prefs = homie.get_prefs()
        self.token = token or os.environ.get('TELEGRAM_BOT_TOKEN') or self.prefs.get('telegramToken', '')
        self.allowed_users = allowed_users if allowed_users is not None else self.prefs.get('telegramAllowedUsers', [])
        # Ensure allowed_users are integers/strings
        self.allowed_users = [str(u) for u in self.allowed_users if u]
        self.offset = 0
        self.running = False
        self._thread = None
        self._voice_lock = threading.Lock()
        self.pending_actions = {}
        self._ram_alert_active = False
        self._battery_alert_active = False

        import notification_mirror
        import presence_monitor
        self.notification_mirror = notification_mirror.NotificationMirror(
            on_notification_callback=self._on_windows_notification
        )
        self.presence_monitor = presence_monitor.PresenceMonitor(
            on_user_returned_callback=self._on_user_returned
        )
        import focus_tracker
        self.focus_tracker = focus_tracker.FocusTracker()

    def _on_windows_notification(self, app_name, title, body, item):
        """Dispatches incoming Windows toast notifications to paired Telegram users."""
        if not self.prefs.get('notificationMirror', True):
            return
        # If user is in full screen or active meeting, suppress live popups
        if item and item.get('suppressed', False):
            return
        # Whitelist / filter logic: ignore Defender routine scans or empty alerts
        if app_name.lower() in ('windows security', 'antivirus') and 'no threats' in (body or '').lower():
            return
        msg = f"🔔 **[{app_name}]**"
        if title:
            msg += f"\n**{title}**"
        if body:
            msg += f"\n{body}"
        for uid in self.allowed_users:
            self.send_message(uid, msg)

    def _on_user_returned(self, away_dur, missed_events):
        """Optional hook when user returns after idle absence."""
        pass

    def _api_call(self, method, data=None, files=None, timeout=30):
        if not self.token:
            return None
        url = f"{TELEGRAM_API_BASE}/bot{self.token}/{method}"
        try:
            resp = requests.post(url, data=data, files=files, timeout=timeout)
            if resp.status_code == 200:
                return resp.json().get('result')
            else:
                print(f"[Telegram] Error {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[Telegram] Request error: {e}")
        return None

    def send_message(self, chat_id, text, parse_mode="Markdown", reply_markup=None):
        """Sends a text message to Telegram, automatically chunking messages longer than 4000 chars."""
        if not text:
            return None
        raw_text = str(text)

        chunks = []
        if len(raw_text) <= 4000:
            chunks = [raw_text]
        else:
            remaining = raw_text
            while remaining:
                if len(remaining) <= 4000:
                    chunks.append(remaining)
                    break
                split_at = remaining.rfind("\n", 0, 4000)
                if split_at == -1 or split_at < 1500:
                    split_at = 4000
                chunks.append(remaining[:split_at])
                remaining = remaining[split_at:].lstrip()

        last_res = None
        for i, chunk in enumerate(chunks):
            data = {'chat_id': chat_id, 'text': chunk}
            if parse_mode:
                data['parse_mode'] = parse_mode
            if reply_markup and i == len(chunks) - 1:
                data['reply_markup'] = json.dumps(reply_markup) if isinstance(reply_markup, dict) else reply_markup
            res = self._api_call('sendMessage', data=data, timeout=10)
            # If markdown fails due to special characters, retry without parse_mode
            if not res and parse_mode:
                data.pop('parse_mode', None)
                res = self._api_call('sendMessage', data=data, timeout=10)
            last_res = res
        return last_res

    def answer_callback_query(self, callback_query_id, text=None, alert=False):
        """Acknowledges a button click on Telegram."""
        data = {'callback_query_id': callback_query_id}
        if text:
            data['text'] = text
        if alert:
            data['show_alert'] = True
        return self._api_call('answerCallbackQuery', data=data)

    def get_control_panel_markup(self):
        """Constructs the interactive inline keyboard control panel."""
        return {
            "inline_keyboard": [
                [
                    {"text": "⏯ Play / Pause", "callback_data": "action_play_pause"},
                    {"text": "⏭ Next Track", "callback_data": "action_next"},
                    {"text": "🔇 Mute", "callback_data": "action_mute"}
                ],
                [
                    {"text": "📸 Screenshot", "callback_data": "action_screen"},
                    {"text": "👁️ Inspect Screen", "callback_data": "action_inspect"},
                    {"text": "💻 PC Vitals", "callback_data": "action_vitals"}
                ],
                [
                    {"text": "📋 Read Clipboard", "callback_data": "action_clip_read"},
                    {"text": "🧠 Smart Copilot", "callback_data": "action_clip_analyze"},
                    {"text": "📁 Downloads", "callback_data": "action_downloads"}
                ],
                [
                    {"text": "📊 Top Tasks", "callback_data": "action_top"},
                    {"text": "⏰ Timer 5m", "callback_data": "action_timer_5m"},
                    {"text": "🔒 Lock PC", "callback_data": "action_lock"}
                ],
                [
                    {"text": "📜 Run Macro...", "callback_data": "action_macro_list"},
                    {"text": "📋 Catch-up Brief", "callback_data": "action_catchup"}
                ],
                [
                    {"text": "📊 Focus Report", "callback_data": "action_focus_report"},
                    {"text": "🎙️ Meeting Notes", "callback_data": "action_meeting_toggle"}
                ]
            ]
        }

    def request_confirmation(self, chat_id, action_description, action_key, payload):
        """Enforces a confirm/cancel guardrail before executing risky actions."""
        import uuid
        action_id = str(uuid.uuid4())[:8]
        self.pending_actions[action_id] = {
            'action': action_key,
            'payload': payload,
            'description': action_description,
            'expires': time.time() + 45
        }
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Confirm", "callback_data": f"confirm_action_{action_id}"},
                    {"text": "❌ Cancel", "callback_data": f"cancel_action_{action_id}"}
                ]
            ]
        }
        msg = (
            f"⚠️ **Security Confirmation Required**:\n"
            f"Are you sure you want to: **{action_description}**?\n"
            f"_(Expires in 45 seconds)_"
        )
        self.send_message(chat_id, msg, reply_markup=keyboard)

    def send_photo(self, chat_id, photo_path, caption=None):
        """Sends an image to the Telegram chat."""
        if not os.path.exists(photo_path):
            return self.send_message(chat_id, f"File not found: {photo_path}")
        try:
            with open(photo_path, 'rb') as f:
                data = {'chat_id': chat_id}
                if caption:
                    data['caption'] = caption
                files = {'photo': f}
                return self._api_call('sendPhoto', data=data, files=files, timeout=30)
        except Exception as e:
            return self.send_message(chat_id, f"Failed to send image: {e}")

    def send_document(self, chat_id, file_path, caption=None):
        """Sends a file document to the Telegram chat."""
        if not os.path.exists(file_path):
            return self.send_message(chat_id, f"File not found: {file_path}")
        try:
            with open(file_path, 'rb') as f:
                data = {'chat_id': chat_id}
                if caption:
                    data['caption'] = caption
                files = {'document': f}
                return self._api_call('sendDocument', data=data, files=files, timeout=60)
        except Exception as e:
            return self.send_message(chat_id, f"Failed to send file: {e}")

    def send_voice(self, chat_id, audio_path, caption=None):
        """Sends a spoken voice note or audio reply to Telegram."""
        if not os.path.exists(audio_path):
            return None
        try:
            with open(audio_path, 'rb') as f:
                data = {'chat_id': chat_id}
                if caption:
                    data['caption'] = caption
                files = {'voice': f}
                res = self._api_call('sendVoice', data=data, files=files, timeout=30)
                if not res:
                    f.seek(0)
                    files = {'audio': f}
                    data['title'] = 'Homie Spoken Reply'
                    data['performer'] = 'Homie'
                    res = self._api_call('sendAudio', data=data, files=files, timeout=30)
                return res
        except Exception as e:
            print(f"[Telegram] Failed to send voice message: {e}")
            return None

    def handle_callback(self, chat_id, callback_query_id, data):
        """Handles interactive inline keyboard button clicks."""
        self.answer_callback_query(callback_query_id)

        if data == 'action_play_pause':
            ok, msg = windows_tools.control_media('play_pause')
            self.send_message(chat_id, f"🎵 {msg}")

        elif data == 'action_next':
            ok, msg = windows_tools.control_media('next')
            self.send_message(chat_id, f"🎵 {msg}")

        elif data == 'action_mute':
            ok, msg = windows_tools.control_media('mute')
            self.send_message(chat_id, f"🎵 {msg}")

        elif data == 'action_screen':
            self.send_message(chat_id, "📸 Capturing desktop...")
            screens = windows_tools.capture_screens()
            if screens:
                for idx, sc in enumerate(screens):
                    self.send_photo(chat_id, sc, caption=f"Display {idx + 1} ({time.strftime('%I:%M:%S %p')})")
            else:
                self.send_message(chat_id, "Could not capture display.")

        elif data == 'action_inspect':
            self.send_message(chat_id, "📸 Capturing desktop and analyzing...")
            screens = windows_tools.capture_screens()
            if screens and os.path.exists(screens[0]):
                self.send_photo(chat_id, screens[0], caption="🖥️ Current Screen")
                import ai_engine
                analysis = ai_engine.run_gemini_vision("What is shown on this screen? Explain key windows and status concisely.", screens[0])
                self.send_message(chat_id, f"👁️ **Screen Analysis**:\n\n{analysis}")
            else:
                self.send_message(chat_id, "Could not capture screen.")

        elif data == 'action_vitals':
            v = windows_tools.get_system_vitals()
            msg = (
                f"💻 **PC Health Snapshot**:\n\n"
                f"• 🧠 **RAM**: {v['ram_pct']}% used ({v['ram_avail_gb']} GB free / {v['ram_total_gb']} GB)\n"
                f"• 💽 **Disk (C:)**: {v['disk_free_gb']} GB free / {v['disk_total_gb']} GB\n"
                f"• 🔋 **Power**: {v['battery']}\n"
                f"• ⏱️ **Uptime**: {v['uptime_hours']} hours\n"
                f"• 🪟 **Active**: `{v['active_window']}`"
            )
            self.send_message(chat_id, msg)

        elif data == 'action_clip_read':
            clip = windows_tools.get_clipboard_text()
            if clip:
                self.send_message(chat_id, f"📋 **PC Clipboard**:\n```\n{clip[:3000]}\n```")
            else:
                self.send_message(chat_id, "📋 PC Clipboard is currently empty.")

        elif data == 'action_clip_analyze':
            analysis = homie.analyze_clipboard()
            self.send_message(chat_id, analysis)

        elif data == 'action_downloads':
            dl = windows_tools.list_downloads(limit=8)
            if not dl:
                self.send_message(chat_id, "📁 Downloads folder is empty.")
            else:
                items = "\n".join(f"• `{d['name']}` ({d['size_mb']} MB, {d['mtime']})" for d in dl)
                self.send_message(chat_id, f"📁 **Recent Downloads**:\n{items}")

        elif data == 'action_top':
            self.handle_command(chat_id, '/top')

        elif data == 'action_timer_5m':
            self.handle_command(chat_id, '/timer 5m Timer finished!')

        elif data == 'action_lock':
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            self.send_message(chat_id, "🔒 PC locked successfully.")

        elif data == 'action_macro_list':
            macros = homie.get_macros()
            buttons = []
            for name in list(macros.keys())[:8]:
                buttons.append([{"text": f"▶️ {name.capitalize()}", "callback_data": f"run_macro_{name}"}])
            keyboard = {"inline_keyboard": buttons}
            self.send_message(chat_id, "📜 **Tap a macro to run on PC**:", reply_markup=keyboard)

        elif data == 'action_catchup':
            self.handle_command(chat_id, '/catchup')

        elif data.startswith('act_pill_'):
            action_id = data[9:]
            import action_pill
            clip = windows_tools.get_clipboard_text()
            ok, msg = action_pill.execute_action(action_id, clip)
            prefix = "✓" if ok else "⚠️"
            self.send_message(chat_id, f"{prefix} {msg}")

        elif data.startswith('getfile_'):
            import file_indexer
            try:
                fid = int(data[8:])
                rec = file_indexer.get_file_by_id(fid)
                if not rec or not os.path.exists(rec['file_path']):
                    self.send_message(chat_id, "⚠️ File not found on disk.")
                    return
                fpath = rec['file_path']
                fname = rec['file_name']
                sz = file_indexer.format_file_size(rec['size_bytes'])
                self.send_message(chat_id, f"📤 Sending `{fname}` ({sz})...")
                self.send_document(chat_id, fpath, caption=f"📄 {fname}")
            except Exception as e:
                self.send_message(chat_id, f"Failed to retrieve file: {e}")

        elif data == 'action_focus_report':
            self.handle_command(chat_id, '/focus')

        elif data == 'action_meeting_toggle':
            import meeting_notes
            sess = meeting_notes.get_meeting_session()
            if sess.is_active:
                self.handle_command(chat_id, '/meeting stop')
            else:
                self.handle_command(chat_id, '/meeting start Quick Meeting')

        elif data.startswith('run_macro_'):
            macro_name = data[10:]
            ok, msg = homie.execute_macro(macro_name)
            self.send_message(chat_id, f"📜 {msg}")

        elif data.startswith('kill_pid_'):
            pid = data[9:]
            self.request_confirmation(chat_id, f"Terminate process PID {pid}", "kill_pid", pid)

        elif data.startswith('confirm_action_'):
            action_id = data[15:]
            item = self.pending_actions.pop(action_id, None)
            if not item:
                self.send_message(chat_id, "⚠️ Action expired or already completed.")
                return
            if time.time() > item['expires']:
                self.send_message(chat_id, "⌛ Action confirmation timed out.")
                return
            act = item['action']
            payload = item['payload']
            if act == 'close_app':
                ok, msg = windows_tools.close_app(payload)
                self.send_message(chat_id, f"🛑 {msg}")
            elif act == 'kill_pid':
                ok, msg = windows_tools.kill_process_by_pid(payload)
                self.send_message(chat_id, f"🛑 {msg}")
            elif act == 'run_cmd':
                ok, out = windows_tools.execute_safe_command(payload)
                self.send_message(chat_id, f"⚡ **Executed**:\n```\n{out}\n```")

        elif data.startswith('cancel_action_'):
            action_id = data[14:]
            self.pending_actions.pop(action_id, None)
            self.send_message(chat_id, "❌ Action cancelled safely.")

    def _vitals_monitor_worker(self):
        """Background daemon monitoring PC RAM and battery, sending proactive alerts with hysteresis."""
        time.sleep(15)
        while self.running:
            try:
                if self.allowed_users:
                    v = windows_tools.get_system_vitals()
                    ram_pct = v.get('ram_pct', 0)

                    # RAM alert: trigger at >= 92%, clear at < 82%
                    if ram_pct >= 92 and not self._ram_alert_active:
                        self._ram_alert_active = True
                        import event_log
                        event_log.log_event("vitals", f"High RAM alert: {ram_pct}% used ({v['ram_total_gb']} GB total)")
                        for uid in self.allowed_users:
                            self.send_message(
                                uid,
                                f"⚠️ **PC Vitals Alert**: High RAM usage ({ram_pct}% used / {v['ram_total_gb']} GB).\nActive Window: `{v['active_window']}`"
                            )
                    elif ram_pct < 82:
                        self._ram_alert_active = False

                    # Battery alert: trigger at <= 15% on battery, clear at >= 25% or plugged in
                    bat = v.get('battery', '')
                    if "On battery" in bat:
                        m = re.search(r'(\d+)%', bat)
                        if m:
                            level = int(m.group(1))
                            if level <= 15 and not self._battery_alert_active:
                                self._battery_alert_active = True
                                import event_log
                                event_log.log_event("vitals", f"Low battery warning: {level}% remaining on battery")
                                for uid in self.allowed_users:
                                    self.send_message(
                                        uid,
                                        f"🔋 **Low Battery Warning**: PC is at {level}% on battery. Please plug in power."
                                    )
                            elif level >= 25:
                                self._battery_alert_active = False
                    else:
                        self._battery_alert_active = False
            except Exception:
                pass
            time.sleep(45)

    def _reminder_monitor_worker(self):
        """Background daemon checking for due reminders and timers."""
        import reminder_scheduler
        while self.running:
            try:
                due = reminder_scheduler.get_due_reminders()
                for it in due:
                    reminder_scheduler.mark_reminder_fired(it['id'])
                    import event_log
                    event_log.log_event("reminder", f"Timer / reminder alert: {it['message']}")
                    cid = it['chat_id']
                    msg = f"⏰ **Timer / Reminder Alert**:\n\n{it['message']}"
                    self.send_message(cid, msg)

                    # If voice replies are enabled, synthesize audio alert
                    if self.prefs.get('voiceReplies', False):
                        try:
                            import voice
                            tmp_wav = os.path.join(tempfile.gettempdir(), f"reminder_{it['id']}.wav")
                            voice.synthesize_speech_to_wav(f"Reminder: {it['message']}", tmp_wav)
                            self.send_voice(cid, tmp_wav)
                            if os.path.exists(tmp_wav):
                                os.remove(tmp_wav)
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(3)

    def download_file(self, file_id, dest_path):
        """Downloads a voice or media file from Telegram servers."""
        file_info = self._api_call('getFile', data={'file_id': file_id})
        if not file_info or 'file_path' not in file_info:
            return False
        remote_path = file_info['file_path']
        download_url = f"{TELEGRAM_API_BASE}/file/bot{self.token}/{remote_path}"
        try:
            resp = requests.get(download_url, timeout=30)
            if resp.status_code == 200:
                with open(dest_path, 'wb') as f:
                    f.write(resp.content)
                return True
        except Exception as e:
            print(f"[Telegram] File download error: {e}")
        return False

    def is_user_authorized(self, user_id, chat_id):
        """Verifies if the sender is authorized to control this PC."""
        uid_str = str(user_id)
        if not self.allowed_users:
            self.allowed_users = [uid_str]
            self.prefs['telegramAllowedUsers'] = self.allowed_users
            homie.save_pref('telegramAllowedUsers', self.allowed_users)
            print(f"[Telegram] Automatically paired owner user ID: {uid_str}", flush=True)
            self.send_message(
                chat_id,
                f"🛡️ **Security Pairing Complete!**\n"
                f"You ({uid_str}) are now the authorized owner of this PC.\n"
                f"You can now send voice notes, /screen, /lock, /media, or any text command!"
            )
            return True
        return uid_str in self.allowed_users

    def handle_command(self, chat_id, text):
        """Processes special Telegram slash commands."""
        cmd = text.strip().split()[0].lower()
        args = text.strip().split()[1:]

        if cmd in ('/start', '/help'):
            msg = (
                "👋 **Hello! I'm Homie on your PC.**\n\n"
                "You can talk to me like a walkie-talkie or send commands from anywhere:\n\n"
                "🎙️ **Voice Notes**: Hold mic button, speak, and release!\n"
                "🎛️ `/panel` - Interactive 1-tap control buttons\n"
                "📋 `/catchup [hours]` - Timeline of what happened while away\n"
                "🖥️ `/focus` - Daily application screen-time & focus report\n"
                "🎙️ `/meeting <start|stop>` - System audio loopback notes & brief\n"
                "🔍 `/find <query>` - Instant file search across Desktop & Downloads\n"
                "🔔 `/mirror <on|off>` - Mirror Windows toast notifications\n"
                "🧠 `/smartclip` - AI analysis & action pill for current clipboard\n"
                "📜 `/macros` / `/macro <name>` - Automated workflows\n"
                "🖼️ **Photos**: Send photo for instant Vision AI analysis\n"
                "📸 `/screen` - Take live desktop screenshot\n"
                "👁️ `/inspect <question>` - Screen capture + Vision answer\n"
                "💻 `/status` - RAM, Disk, Battery, Uptime, Active Window\n"
                "📊 `/top` - Top CPU/RAM processes with kill buttons\n"
                "⏰ `/remind <10m> <msg>` - Persistent timer/reminder\n"
                "🗣️ `/speak <text>` - Offline Windows SAPI voice synthesis\n"
                "📋 `/clip [text]` - Read or set PC clipboard\n"
                "⚡ `/cmd <command>` - Execute safe Windows shell command\n"
                "📁 `/downloads` - List recent files in Downloads folder\n"
                "📤 `/get <filename>` - Send file from PC to Telegram\n"
                "▶️ `/play <song>` - Autoplay YouTube music/video\n"
                "🎵 `/media <pause|play|next|mute|volup>` - Media control\n"
                "💬 `/msg <whatsapp|telegram> <contact> <text>` - Send chat\n"
                "🔒 `/lock` - Lock your Windows PC\n"
                "🛑 `/kill <app>` - Kill app with confirmation\n"
                "🪟 `/snap <left|right|full|center>` - Window placement\n"
                "🚀 `/open <app>` - Launch application\n"
                "🧠 `/rules` / `/remember <fact>` - Long-term memory\n\n"
                "💬 Or tap any button below for instant action:"
            )
            self.send_message(chat_id, msg, reply_markup=self.get_control_panel_markup())
            return

        if cmd == '/panel':
            self.send_message(
                chat_id,
                "🎛️ **Homie Remote Control Panel**\nTap any button below for 1-tap PC control:",
                reply_markup=self.get_control_panel_markup()
            )
            return

        if cmd in ('/smartclip', '/copilot'):
            clip = windows_tools.get_clipboard_text()
            if not clip or not clip.strip():
                self.send_message(chat_id, "📋 Clipboard is currently empty.")
                return
            import clipboard_classifier
            import action_pill
            cls = clipboard_classifier.classify_clipboard_content(clip)
            analysis = homie.analyze_clipboard(clip)
            acts = action_pill.get_actions_for_classification(cls)
            buttons = []
            if acts:
                row = []
                for a in acts:
                    row.append({"text": a['label'], "callback_data": f"act_pill_{a['id']}"})
                buttons.append(row)
            keyboard = {"inline_keyboard": buttons} if buttons else None
            self.send_message(chat_id, analysis, reply_markup=keyboard)
            return

        if cmd in ('/catchup', '/missed', '/brief'):
            hours = 4
            if args and args[0].isdigit():
                hours = max(1, min(72, int(args[0])))
            import event_log
            since_ts = time.time() - (hours * 3600)
            events = event_log.get_events_since(since_ts, limit=25)
            if not events:
                self.send_message(chat_id, f"✨ **All Quiet**: No alerts or notable events recorded in the last {hours} hour(s).")
                return

            type_icons = {
                'notification': '🔔',
                'presence': '🚶',
                'vitals': '⚠️',
                'reminder': '⏰',
                'command': '⚡'
            }
            lines = [f"📋 **What Did I Miss? (Past {hours} hours)**:\n"]
            for e in events:
                t_str = time.strftime("%I:%M %p", time.localtime(e['occurred_at']))
                icon = type_icons.get(e['event_type'], '•')
                lines.append(f"{icon} `{t_str}`: {e['event_summary']}")

            self.send_message(chat_id, "\n".join(lines))
            return

        if cmd in ('/find', '/search'):
            query = " ".join(args).strip()
            if not query:
                self.send_message(chat_id, "Usage: `/find <filename_or_keyword>` (e.g. `/find resume` or `/find report.pdf`)")
                return
            import file_indexer
            matches = file_indexer.search_files(query, limit=8)
            if not matches:
                # If index was empty or 0 matches, auto-build index
                self.send_message(chat_id, f"🔍 Indexing Desktop, Downloads, Documents for '{query}'...")
                file_indexer.build_file_index()
                matches = file_indexer.search_files(query, limit=8)

            if not matches:
                self.send_message(chat_id, f"🔍 No files found matching `{query}`.")
                return

            lines = [f"🔍 **Found {len(matches)} file(s) matching '{query}'**:\n"]
            buttons = []
            for f in matches:
                sz = file_indexer.format_file_size(f['size_bytes'])
                lines.append(f"• `{f['file_name']}` ({sz})")
                buttons.append([{"text": f"📥 Send {f['file_name'][:25]} ({sz})", "callback_data": f"getfile_{f['id']}"}])

            keyboard = {"inline_keyboard": buttons}
            self.send_message(chat_id, "\n".join(lines), reply_markup=keyboard)
            return

        if cmd == '/index':
            self.send_message(chat_id, "🔍 Rebuilding local file search index...")
            import file_indexer
            count = file_indexer.build_file_index()
            self.send_message(chat_id, f"✓ Indexed **{count}** files across Desktop, Downloads, and Documents.")
            return

        if cmd == '/mirror':
            sub = args[0].lower() if args else ""
            if sub in ('on', 'true', 'enable'):
                self.prefs['notificationMirror'] = True
                homie.save_pref('notificationMirror', True)
                self.send_message(chat_id, "🔔 **Windows Notification Mirroring**: ON\nIncoming toast alerts will be forwarded directly to your phone.")
            elif sub in ('off', 'false', 'disable'):
                self.prefs['notificationMirror'] = False
                homie.save_pref('notificationMirror', False)
                self.send_message(chat_id, "🔕 **Windows Notification Mirroring**: OFF")
            else:
                curr = "ON" if self.prefs.get('notificationMirror', True) else "OFF"
                self.send_message(chat_id, f"🔔 **Windows Notification Mirroring**: {curr}\nUse `/mirror on` or `/mirror off` to toggle.")
            return

        if cmd in ('/focus', '/focusreport', '/screentime'):
            hours = 24
            if args and args[0].isdigit():
                hours = max(1, min(168, int(args[0])))
            import focus_tracker
            report = focus_tracker.get_focus_report(lookback_hours=hours)
            if not report:
                self.send_message(chat_id, f"🖥 **Focus Report**: No window activity recorded in the past {hours} hour(s).")
                return
            lines = [f"🖥 **PC Productivity Focus Report (Past {hours}h)**:\n"]
            for r in report:
                lines.append(f"• `{r['application_name']}`: **{r['formatted_duration']}** ({r['percent']}%)")
            self.send_message(chat_id, "\n".join(lines))
            return

        if cmd == '/meeting':
            sub = args[0].lower() if args else ""
            import meeting_notes
            sess = meeting_notes.get_meeting_session()

            if sub in ('start', 'record', 'begin'):
                m_title = " ".join(args[1:]) if len(args) > 1 else "Team Discussion"
                ok, msg = sess.start_meeting(m_title)
                self.send_message(chat_id, msg)
                return

            elif sub in ('stop', 'end', 'finish'):
                self.send_message(chat_id, "⏹️ Concluding meeting and compiling summary...")
                ok, res = sess.stop_meeting()
                if not ok:
                    self.send_message(chat_id, f"⚠️ {res}")
                    return

                self.send_message(chat_id, f"{res['summary']}")

                # Voice reply if enabled
                if self.prefs.get('voiceReplies', False):
                    try:
                        import voice
                        tmp_wav = os.path.join(tempfile.gettempdir(), f"meeting_{res['id']}.wav")
                        voice.synthesize_speech_to_wav(f"Meeting concluded for {res['title']}. Duration: {res['duration_formatted']}.", tmp_wav)
                        self.send_voice(chat_id, tmp_wav)
                        if os.path.exists(tmp_wav):
                            os.remove(tmp_wav)
                    except Exception:
                        pass
                return

            elif sub == 'status':
                if sess.is_active:
                    dur_m = round((time.time() - sess.started_at) / 60.0, 1)
                    self.send_message(chat_id, f"🎙️ **Active Meeting**: '{sess.title}' ({dur_m} min elapsed)")
                else:
                    self.send_message(chat_id, "⏹️ No meeting currently recording. Use `/meeting start <title>`.")
                return

            else:
                self.send_message(chat_id, "Usage: `/meeting start <title>` or `/meeting stop`")
                return

        if cmd == '/meetings':
            import meeting_notes
            recent = meeting_notes.list_recent_meetings(limit=5)
            if not recent:
                self.send_message(chat_id, "📝 No past recorded meetings found.")
                return
            lines = ["📝 **Recent Recorded Meetings**:\n"]
            for m in recent:
                t_str = time.strftime("%b %d, %I:%M %p", time.localtime(m['started_at']))
                dur_m = round(m['duration_seconds'] / 60.0, 1)
                lines.append(f"• **{m['title']}** ({dur_m}m) - `{t_str}`")
            self.send_message(chat_id, "\n".join(lines))
            return

        if cmd in ('/macros', '/macro'):
            if args and cmd == '/macro':
                macro_name = args[0]
                ok, msg = homie.execute_macro(macro_name)
                self.send_message(chat_id, f"📜 {msg}")
                return
            macros = homie.get_macros()
            buttons = []
            for name in list(macros.keys())[:8]:
                buttons.append([{"text": f"▶️ Run {name.capitalize()}", "callback_data": f"run_macro_{name}"}])
            keyboard = {"inline_keyboard": buttons}
            self.send_message(chat_id, "📜 **Workflow Macros**:\nTap to run or use `/macro <name>`:", reply_markup=keyboard)
            return

        if cmd in ('/play', '/yt', '/youtube'):
            target = " ".join(args)
            if not target:
                self.send_message(chat_id, "Usage: `/play <song or video name>` (e.g. `/play telugu music`)")
                return
            ok, msg = windows_tools.play_youtube(target)
            self.send_message(chat_id, f"▶️ {msg}")
            return

        if cmd in ('/screen', '/screens', '/screenshot'):
            self.send_message(chat_id, "📸 Capturing desktop...")
            screens = windows_tools.capture_screens()
            if screens:
                for idx, sc in enumerate(screens):
                    caption = f"Display {idx + 1} ({time.strftime('%I:%M:%S %p')})"
                    self.send_photo(chat_id, sc, caption=caption)
            else:
                self.send_message(chat_id, "Could not capture display.")
            return

        if cmd == '/lock':
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            self.send_message(chat_id, "🔒 Workstation locked successfully.")
            return

        if cmd in ('/media', '/pause', '/resume', '/playpause', '/next', '/prev', '/previous', '/mute', '/volup', '/voldown'):
            if cmd == '/media':
                action = args[0] if args else "play_pause"
            else:
                action = cmd.lstrip('/')
            ok, msg = windows_tools.control_media(action)
            self.send_message(chat_id, f"🎵 {msg}")
            return

        if cmd == '/snap':
            where = args[0] if args else "full"
            app = args[1] if len(args) > 1 else ""
            ok, msg = windows_tools.place_window(app, where)
            self.send_message(chat_id, f"🪟 {msg}")
            return

        if cmd == '/open':
            target = " ".join(args)
            if not target:
                self.send_message(chat_id, "Usage: `/open <app_name>`")
                return
            ok, msg = windows_tools.launch_app(target)
            self.send_message(chat_id, f"🚀 {msg}")
            return

        if cmd in ('/close', '/kill', '/terminate'):
            target = " ".join(args).strip()
            if not target:
                self.send_message(chat_id, "Usage: `/close <app_name>` or `/kill <app_name>`")
                return
            # Safety confirmation guardrail for destructive kill actions
            if cmd in ('/kill', '/terminate') or 'force' in text.lower():
                self.request_confirmation(chat_id, f"Terminate process '{target}'", "close_app", target)
                return
            ok, msg = windows_tools.close_app(target)
            self.send_message(chat_id, f"🛑 {msg}")
            return

        if cmd in ('/top', '/ps', '/processes'):
            procs = windows_tools.get_top_processes(sort_by='memory', limit=8)
            if not procs:
                self.send_message(chat_id, "No process metrics available.")
                return
            lines = ["📊 **Top Resource Consumers (by RAM)**:\n"]
            buttons = []
            for p in procs:
                lines.append(f"• `{p['name']}` (PID {p['pid']}): {p['mem_pct']}% ({p['mem_mb']} MB) | CPU: {p['cpu_pct']}%")
                if p['name'].lower() not in windows_tools.PROTECTED_PROCESS_NAMES:
                    buttons.append([{"text": f"🛑 Kill {p['name']} ({p['pid']})", "callback_data": f"kill_pid_{p['pid']}"}])
            keyboard = {"inline_keyboard": buttons[:5]} if buttons else None
            self.send_message(chat_id, "\n".join(lines), reply_markup=keyboard)
            return

        if cmd in ('/remind', '/timer'):
            if not args:
                self.send_message(chat_id, "Usage: `/remind <10m|1h|30s> <message>` (e.g. `/remind 10m check laundry`)")
                return
            dur = args[0]
            remind_msg = " ".join(args[1:]) if len(args) > 1 else "Timer finished!"
            try:
                import reminder_scheduler
                reminder_scheduler.add_reminder(chat_id, dur, remind_msg)
                self.send_message(chat_id, f"⏰ **Timer Set**!\nI will alert you in **{dur}**: \"{remind_msg}\"")
            except Exception as e:
                self.send_message(chat_id, f"Failed to set reminder: {e}")
            return

        if cmd in ('/reminders', '/timers'):
            import reminder_scheduler
            active = reminder_scheduler.list_active_reminders(chat_id)
            if not active:
                self.send_message(chat_id, "⏰ No active timers. Set one with `/remind 10m <message>`.")
            else:
                lines = ["⏰ **Active Scheduled Reminders**:"]
                for a in active:
                    rem_sec = max(0, int(a['fire_at'] - time.time()))
                    rem_min = round(rem_sec / 60, 1)
                    lines.append(f"• \"{a['message']}\" (in {rem_min} min)")
                self.send_message(chat_id, "\n".join(lines))
            return

        if cmd in ('/speak', '/tts'):
            text_to_speak = " ".join(args).strip()
            if not text_to_speak:
                self.send_message(chat_id, "Usage: `/speak <text to synthesize>`")
                return
            try:
                import voice
                tmp_wav = os.path.join(tempfile.gettempdir(), f"speak_{int(time.time())}.wav")
                voice.synthesize_speech_to_wav(text_to_speak, tmp_wav)
                self.send_voice(chat_id, tmp_wav, caption=f"🗣️ \"{text_to_speak[:100]}\"")
                if os.path.exists(tmp_wav):
                    os.remove(tmp_wav)
            except Exception as e:
                self.send_message(chat_id, f"TTS synthesis error: {e}")
            return

        if cmd == '/voicereply':
            arg = args[0].lower() if args else ""
            if arg in ('on', 'enable', 'true'):
                self.prefs['voiceReplies'] = True
                homie.save_pref('voiceReplies', True)
                self.send_message(chat_id, "🎙️ Voice replies enabled! Homie will speak back.")
            elif arg in ('off', 'disable', 'false'):
                self.prefs['voiceReplies'] = False
                homie.save_pref('voiceReplies', False)
                self.send_message(chat_id, "🔇 Voice replies disabled (text only).")
            else:
                curr = "ON" if self.prefs.get('voiceReplies', False) else "OFF"
                self.send_message(chat_id, f"Voice replies are currently **{curr}**. Use `/voicereply on` or `/voicereply off`.")
            return

        if cmd in ('/status', '/pc', '/vitals', '/health'):
            v = windows_tools.get_system_vitals()
            msg = (
                f"💻 **PC Health Snapshot**:\n\n"
                f"• 🧠 **RAM**: {v['ram_pct']}% used ({v['ram_avail_gb']} GB free / {v['ram_total_gb']} GB)\n"
                f"• 💽 **Disk (C:)**: {v['disk_free_gb']} GB free / {v['disk_total_gb']} GB\n"
                f"• 🔋 **Power**: {v['battery']}\n"
                f"• ⏱️ **Uptime**: {v['uptime_hours']} hours\n"
                f"• 🪟 **Active**: `{v['active_window']}`"
            )
            self.send_message(chat_id, msg)
            return

        if cmd in ('/whoami', '/id'):
            self.send_message(chat_id, f"👤 **Telegram Identity**:\n• Chat ID: `{chat_id}`\n• Authorized Users: `{self.allowed_users}`")
            return

        if cmd in ('/clip', '/clipboard'):
            if args:
                to_copy = " ".join(args)
                ok, msg = windows_tools.set_clipboard_text(to_copy)
                self.send_message(chat_id, f"📋 {msg}")
            else:
                clip = windows_tools.get_clipboard_text()
                if clip:
                    self.send_message(chat_id, f"📋 **PC Clipboard**:\n```\n{clip[:3000]}\n```")
                else:
                    self.send_message(chat_id, "📋 PC Clipboard is currently empty.")
            return

        if cmd == '/cmd':
            command = " ".join(args)
            if not command:
                self.send_message(chat_id, "Usage: `/cmd <windows command>` (e.g. `/cmd git status` or `/cmd ipconfig`)")
                return
            self.send_message(chat_id, f"⚡ Executing: `{command}`...")
            ok, out = windows_tools.execute_safe_command(command)
            prefix = "✓" if ok else "⚠️"
            self.send_message(chat_id, f"{prefix} **Output**:\n```\n{out}\n```")
            return

        if cmd == '/get':
            target = " ".join(args).strip()
            if not target:
                self.send_message(chat_id, "Usage: `/get <path_or_filename>` (e.g. `/get notes.txt`)")
                return
            resolved_path = None
            candidates = [
                target,
                os.path.join(os.getcwd(), target),
                os.path.join(os.path.expanduser("~"), "Downloads", target),
                os.path.join(os.path.expanduser("~"), "Desktop", target),
                os.path.join(os.path.expanduser("~"), "Documents", target)
            ]
            for c in candidates:
                if os.path.isfile(c):
                    resolved_path = c
                    break
            if resolved_path:
                self.send_message(chat_id, f"📤 Sending `{os.path.basename(resolved_path)}`...")
                self.send_document(chat_id, resolved_path, caption=f"📄 {os.path.basename(resolved_path)}")
            else:
                self.send_message(chat_id, f"File not found: '{target}' across common folders.")
            return

        if cmd in ('/downloads', '/dl'):
            dl = windows_tools.list_downloads(limit=10)
            if not dl:
                self.send_message(chat_id, "📁 Downloads folder is empty.")
                return
            items = "\n".join(f"• `{d['name']}` ({d['size_mb']} MB, {d['mtime']})" for d in dl)
            self.send_message(chat_id, f"📁 **Recent PC Downloads**:\n{items}\n\nUse `/get <filename>` to send any file here.")
            return

        if cmd == '/inspect':
            question = " ".join(args) or "What is currently on the screen?"
            self.send_message(chat_id, f"📸 Capturing desktop and analyzing: \"{question}\"...")
            screens = windows_tools.capture_screens()
            if screens and os.path.exists(screens[0]):
                self.send_photo(chat_id, screens[0], caption="🖥️ Current Screen")
                import ai_engine
                analysis = ai_engine.run_gemini_vision(question, screens[0])
                self.send_message(chat_id, f"👁️ **Screen Analysis**:\n\n{analysis}")
            else:
                self.send_message(chat_id, "Could not capture screen for analysis.")
            return

        if cmd in ('/rules', '/memory'):
            rules = homie.get_rules()
            if not rules:
                self.send_message(chat_id, "🧠 No rules stored yet. Use `/remember <rule>` to teach Homie facts or habits.")
            else:
                formatted = "\n".join(f"• {r}" for r in rules)
                self.send_message(chat_id, f"🧠 **Homie Long-Term Memory**:\n{formatted}")
            return

        if cmd == '/remember':
            rule = " ".join(args).strip()
            if not rule:
                self.send_message(chat_id, "Usage: `/remember <rule or fact>`")
                return
            msg = homie.add_rule(rule)
            self.send_message(chat_id, f"🧠 {msg}")
            return

        if cmd == '/forget':
            words = " ".join(args).strip()
            if not words:
                self.send_message(chat_id, "Usage: `/forget <words>`")
                return
            msg = homie.remove_rule(words)
            self.send_message(chat_id, f"🧠 {msg}")
            return

        if cmd in ('/msg', '/say', '/send'):
            if len(args) < 2:
                self.send_message(chat_id, "Usage: `/msg <whatsapp|telegram> [recipient] <message>`")
                return
            app = args[0].lower()
            if app not in ('whatsapp', 'telegram'):
                app = 'whatsapp'
                recipient = args[0]
                message = " ".join(args[1:])
            else:
                recipient = args[1] if len(args) > 2 else ""
                message = " ".join(args[2:]) if len(args) > 2 else args[1]
            ok, res = windows_tools.send_chat_message(app, recipient=recipient, message=message)
            self.send_message(chat_id, f"💬 {res}")
            return

        # Regular prompt -> Run through Homie
        self.process_homie_task(chat_id, text)

    def process_homie_task(self, chat_id, text):
        """Runs the query through instant local commands or AI."""
        # 1. Fast local command check
        handled, fast_msg = homie.try_fast_command(text)
        if handled:
            self.send_message(chat_id, f"✓ {fast_msg}")
            return

        # 2. Free AI Provider (Gemini / NVIDIA NIM)
        self.send_message(chat_id, "🧠 *Thinking...*")
        
        steps = []
        def on_step(line):
            steps.append(line)

        result = homie.run_ai(text, step_callback=on_step)
        
        reply = ""
        if steps:
            reply += "\n".join(f"`{s}`" for s in steps[:3]) + "\n\n"
        reply += result
        self.send_message(chat_id, reply)

    def process_voice_message(self, chat_id, voice_file_id):
        """Transcribes incoming voice note from phone and executes task."""
        self.send_message(chat_id, "🎧 *Listening to your voice note...*")
        
        tmp_dir = tempfile.gettempdir()
        audio_path = os.path.join(tmp_dir, f"telegram_voice_{int(time.time())}.ogg")

        if not self.download_file(voice_file_id, audio_path):
            self.send_message(chat_id, "Failed to download voice note.")
            return

        try:
            with self._voice_lock:
                # Decode audio to numpy array and transcribe
                audio_array = decode_audio_file(audio_path)
                if audio_array is None or len(audio_array) == 0:
                    self.send_message(chat_id, "Could not decode audio file.")
                    return

                model = get_whisper_model()
                segments, _ = model.transcribe(
                    audio_array,
                    beam_size=5,
                    vad_filter=True,
                    language="en"
                )
                transcript = " ".join(s.text.strip() for s in segments).strip()

                if not transcript:
                    self.send_message(chat_id, "I couldn't hear any clear words in that voice note.")
                    return

                print(f"[Telegram] Transcribed voice note from {chat_id}: \"{transcript}\"", flush=True)
                self.send_message(chat_id, f"🗣️ *Heard:* \"{transcript}\"")
                self.process_homie_task(chat_id, transcript)
        except Exception as e:
            print(f"[Telegram] Voice note processing error: {e}", flush=True)
            self.send_message(chat_id, f"Transcription error: {e}")
        finally:
            if os.path.exists(audio_path):
                try:
                    os.remove(audio_path)
                except Exception:
                    pass

    def process_photo_message(self, chat_id, photo_file_id, caption=""):
        """Downloads photo sent from phone, passes to Gemini Vision, and replies with analysis."""
        self.send_message(chat_id, "🖼️ *Inspecting photo with Vision AI...*")
        tmp_path = os.path.join(tempfile.gettempdir(), f"telegram_photo_{int(time.time())}.jpg")
        try:
            ok = self.download_file(photo_file_id, tmp_path)
            if not ok or not os.path.exists(tmp_path):
                self.send_message(chat_id, "Failed to download image from Telegram.")
                return

            import ai_engine
            prompt = caption or "What is in this image? Explain key details, text, and any errors clearly."
            analysis = ai_engine.run_gemini_vision(prompt, tmp_path)
            self.send_message(chat_id, f"👁️ **Vision Analysis**:\n\n{analysis}")
        except Exception as e:
            self.send_message(chat_id, f"Vision inspection error: {e}")
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def process_document_message(self, chat_id, doc_file_id, file_name="", caption=""):
        """Smart File Drop Zone: accepts uploaded documents/code/logs and automatically analyzes them."""
        save_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        if "#desktop" in (caption or "").lower():
            save_dir = os.path.join(os.path.expanduser("~"), "Desktop")

        dest_path = os.path.join(save_dir, file_name or f"file_{int(time.time())}")
        try:
            ok = self.download_file(doc_file_id, dest_path)
            if not ok or not os.path.exists(dest_path):
                self.send_message(chat_id, "Failed to download document to PC.")
                return

            size_kb = round(os.path.getsize(dest_path) / 1024, 1)
            self.send_message(
                chat_id,
                f"📥 **Saved File to PC**:\n• Name: `{os.path.basename(dest_path)}`\n• Size: {size_kb} KB\n• Path: `{dest_path}`"
            )

            # Auto-analyze code, logs, and tracebacks
            text_extensions = ('.log', '.txt', '.py', '.js', '.json', '.err', '.cs', '.java', '.cpp', '.md')
            if dest_path.lower().endswith(text_extensions) or '#analyze' in (caption or "").lower():
                try:
                    with open(dest_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(4000)
                    if content.strip():
                        self.send_message(chat_id, "🔍 *Analyzing uploaded code/log file...*")
                        import ai_engine
                        prompt = f"Analyze this uploaded file content. Summarize its purpose, and identify any errors, bugs, or anomalies clearly:\n\n```\n{content}\n```"
                        prefs = homie.get_prefs()
                        analysis = ai_engine.run_query(prompt, prefs)
                        self.send_message(chat_id, f"📊 **File Analysis**:\n\n{analysis}")
                except Exception:
                    pass
        except Exception as e:
            self.send_message(chat_id, f"File handling error: {e}")

    def poll_updates(self):
        """Long-polling update loop for Telegram Bot API."""
        print("[Telegram] Bridge started. Listening for remote messages from your phone...", flush=True)
        while self.running:
            try:
                data = {'offset': self.offset, 'timeout': 20}
                updates = self._api_call('getUpdates', data=data, timeout=25)
                if not updates:
                    time.sleep(1)
                    continue

                for u in updates:
                    self.offset = u['update_id'] + 1

                    # 1. Interactive Button Click (Callback Query)
                    if 'callback_query' in u:
                        cq = u['callback_query']
                        cq_id = cq.get('id')
                        cq_user = cq.get('from', {}).get('id')
                        cq_chat = cq.get('message', {}).get('chat', {}).get('id')
                        cq_data = cq.get('data', '')

                        if not self.is_user_authorized(cq_user, cq_chat):
                            self.answer_callback_query(cq_id, "Access denied.", alert=True)
                            continue

                        threading.Thread(target=self.handle_callback, args=(cq_chat, cq_id, cq_data), daemon=True).start()
                        continue

                    msg = u.get('message')
                    if not msg:
                        continue

                    user = msg.get('from', {})
                    user_id = user.get('id')
                    chat_id = msg.get('chat', {}).get('id')

                    # Security Verification
                    if not self.is_user_authorized(user_id, chat_id):
                        self.send_message(chat_id, "⛔ Access denied. This PC belongs to another user.")
                        continue

                    # Voice Note from Phone
                    if 'voice' in msg:
                        voice_id = msg['voice']['file_id']
                        threading.Thread(target=self.process_voice_message, args=(chat_id, voice_id), daemon=True).start()
                    # Audio file
                    elif 'audio' in msg:
                        audio_id = msg['audio']['file_id']
                        threading.Thread(target=self.process_voice_message, args=(chat_id, audio_id), daemon=True).start()
                    # Photo from Phone (multimodal vision inspection)
                    elif 'photo' in msg:
                        photo_id = msg['photo'][-1]['file_id']  # Highest resolution
                        caption = msg.get('caption', '')
                        threading.Thread(target=self.process_photo_message, args=(chat_id, photo_id, caption), daemon=True).start()
                    # Document / File from Phone
                    elif 'document' in msg:
                        doc = msg['document']
                        doc_id = doc['file_id']
                        file_name = doc.get('file_name', '')
                        caption = msg.get('caption', '')
                        threading.Thread(target=self.process_document_message, args=(chat_id, doc_id, file_name, caption), daemon=True).start()
                    # Text Message or Command
                    elif 'text' in msg:
                        text = msg['text']
                        threading.Thread(target=self.handle_command, args=(chat_id, text), daemon=True).start()

            except Exception as e:
                time.sleep(2)

    def start(self):
        """Starts the Telegram bridge in a daemon thread."""
        if not self.token:
            print("[Telegram] No bot token configured. Skipping Telegram bridge.")
            return False
        if self.running:
            return True

        self.running = True
        self._thread = threading.Thread(target=self.poll_updates, daemon=True)
        self._thread.start()

        # Start proactive vitals monitoring in background
        threading.Thread(target=self._vitals_monitor_worker, daemon=True).start()
        # Start reminders and timers monitor in background
        threading.Thread(target=self._reminder_monitor_worker, daemon=True).start()
        # Start Windows toast notification mirror, presence monitor, and focus tracker
        try:
            self.notification_mirror.start()
            self.presence_monitor.start()
            self.focus_tracker.start()
        except Exception as e:
            print(f"[Telegram] Warning starting background monitors: {e}")
        return True

    def stop(self):
        """Stops the Telegram bridge polling."""
        self.running = False
        try:
            self.notification_mirror.stop()
            self.presence_monitor.stop()
            self.focus_tracker.stop()
        except Exception:
            pass

def main():
    token = None
    if len(sys.argv) > 1:
        token = sys.argv[1]
    
    bridge = TelegramBridge(token=token)
    if not bridge.token:
        print("=" * 60)
        print("  Homie Telegram Remote Control Setup")
        print("=" * 60)
        print("1. Open Telegram on your phone and search for: @BotFather")
        print("2. Send: /newbot")
        print("3. Give your bot a name (e.g. 'MyHomieBot') and a username")
        print("4. Copy the API Token (e.g. 123456789:ABC-DEF...)")
        print("5. Set your token via:")
        print("   setx TELEGRAM_BOT_TOKEN \"your_token_here\"")
        print("   OR run: python telegram_bridge.py <your_token>")
        print("=" * 60)
        return

    bridge.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bridge.stop()
        print("\n[Telegram] Bridge stopped.")

if __name__ == '__main__':
    main()
