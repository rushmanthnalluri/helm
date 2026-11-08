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

    def send_message(self, chat_id, text, parse_mode="Markdown"):
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
        for chunk in chunks:
            data = {'chat_id': chat_id, 'text': chunk}
            if parse_mode:
                data['parse_mode'] = parse_mode
            res = self._api_call('sendMessage', data=data, timeout=10)
            # If markdown fails due to special characters, retry without parse_mode
            if not res and parse_mode:
                data.pop('parse_mode', None)
                res = self._api_call('sendMessage', data=data, timeout=10)
            last_res = res
        return last_res

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
                "🎙️ **Voice Messages**: Hold Telegram mic button, speak, and release!\n"
                "📸 `/screen` - Take a live screenshot of your PC\n"
                "💻 `/status` - Check PC RAM, Disk, Battery, and Uptime\n"
                "▶️ `/play <song>` - Instantly play music/video on YouTube\n"
                "🔒 `/lock` - Lock your Windows PC\n"
                "🛑 `/close <app>` - Close an app (e.g. `/close whatsapp`)\n"
                "🪟 `/snap <left|right|full|center>` - Arrange windows\n"
                "🎵 `/media <pause|play|next|mute>` - Control music\n"
                "🚀 `/open <app>` - Launch an app (e.g. `/open spotify`)\n"
                "💬 Or just type anything you want me to do or answer!"
            )
            self.send_message(chat_id, msg)
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

        if cmd == '/close':
            target = " ".join(args)
            if not target:
                self.send_message(chat_id, "Usage: `/close <app_name>`")
                return
            ok, msg = windows_tools.close_app(target)
            self.send_message(chat_id, f"🛑 {msg}")
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
        return True

    def stop(self):
        """Stops the Telegram bridge polling."""
        self.running = False

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
