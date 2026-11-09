# 🏠 Homie: Your whole Windows PC, one sentence away.

<p align="center">
  Hold <kbd>Ctrl</kbd> <kbd>Alt</kbd> <kbd>Space</kbd>, say what you need, let go.<br>
  <b>Homie</b> moves your windows, finds your files, reads your screen, and gets things done on Windows.
</p>

<p align="center">
  <b>🧠 Learns as you use it</b> &nbsp;·&nbsp; <b>⚡ Fast local commands (<50ms)</b> &nbsp;·&nbsp; <b>🔑 No separate API key required</b> &nbsp;·&nbsp; <b>Free and open source</b>
</p>

---

## 🌟 What is Homie?

**Homie** is an open-source desktop voice and chat assistant built natively for **Windows 10 and Windows 11**.

Inspired by macOS's [Atticus](https://github.com/SaarthurR/atticus-mac) by Caleb Writes Code and SaarthurR, Homie brings the concept to Windows with native Windows automation, a compact desktop chat window, and local on-device speech transcription.

### Key Capabilities

- **Hold to talk**: Hold <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>Space</kbd> anywhere in Windows, speak naturally, and release to send.
- **⚡ Instant Commands ($0, <50ms)**: Window snapping, opening apps, media controls, web search, time, and system commands bypass the AI entirely and run in milliseconds.
- **👀 Screen Vision**: Ask *"What's on my screen?"* or *"Where is the save button?"* and Homie takes high-resolution display captures to inspect controls.
- **🪟 Windows Window Management**: *"Put Chrome on the left and VS Code on the right"* snaps windows across any number of monitors while respecting your taskbar.
- **🎙️ On-Device Privacy**: Uses on-device `faster-whisper` (CTranslate2 INT8) for transcription. Your audio never leaves your computer.
- **Compact chat window**: Type or talk in a small, resizable chat with visible transcripts, streamed replies, and a minimize button.
- **🛡️ Safe by Default**: Prompts you with an interactive Allow / Don't Allow card before running destructive operations (`rmdir /s`, `format`, `del /f /q`, system shutdown).
- **🧠 Memory & Rules**: Say *"Remember to always write replies in bullet points"* and every future prompt includes your preferences.

---

## 🔑 Free AI Providers (No Claude Plan Required!)

You do **not** need a paid Claude account. Homie natively supports free cloud API keys as well as local offline models:

| Provider | Free Tier Details | Supported Models |
| :--- | :--- | :--- |
| **Google AI Studio (Gemini)** | **100% Free** (generous limits, multimodal vision) | `gemini-2.0-flash`, `gemini-1.5-flash` |
| **NVIDIA NIM** | **Free API credits** on signup | `meta/llama-3.3-70b-instruct`, `deepseek-ai/deepseek-r1` |
| **Groq Cloud** | **100% Free tier** (blazing fast Llama) | `llama-3.3-70b-versatile` |
| **Local Ollama** | **100% Free & Offline** | `qwen2.5`, `llama3.2`, `mistral` |

### Setting Your Free API Key
You can set your API key in **one command** via PowerShell:

```powershell
# For Google AI Studio (Recommended for screen vision):
setx GEMINI_API_KEY "AIzaSy..."

# For NVIDIA NIM:
setx NVIDIA_API_KEY "nvapi-..."

# For Groq:
setx GROQ_API_KEY "gsk_..."
```

Or configure it in your `~/.config/homie/settings.json`:
```json
{
  "provider": "gemini",
  "model": "gemini-2.0-flash",
  "geminiKey": "AIzaSy..."
}
```

---

## 📱 Message or Send Voice Notes to Your PC from Telegram (100% Free)

You can message Homie from your phone or send a voice note in walkie-talkie style. Homie processes it on your PC and sends a reply:

- 🎙️ **Voice Walkie-Talkie**: Hold the microphone button in Telegram, speak naturally, and send. Homie transcribes your voice with local Whisper, executes the action, and replies back!
- 📸 **Live Desktop Screen**: Send `/screen` to get an instant high-res photo of your Windows displays.
- 🔒 **Lock Workstation**: Send `/lock` from anywhere to immediately lock your PC.
- 🪟 **Window Management**: Send `/snap left` or `/snap right`.
- 🎵 **Media Playback**: Send `/media pause`, `/media play`, or `/media volup`.
- 🚀 **App Launcher**: Send `/open chrome` or `/open notepad`.
- 💬 **Ask Anything**: Any prompt or question is processed by Homie via Gemini / NVIDIA NIM and replied back to your phone.
- 🛡️ **Local one-time pairing**: New installs do not trust the first person who messages the bot. Copy a short-lived pairing command from Homie's Windows tray menu and send it from your private Telegram chat. Group chats cannot control the PC.

### How to Set It Up in 60 Seconds:
1. Open Telegram on your phone and message **`@BotFather`**.
2. Type `/newbot`, give it a name (e.g. `MyHomiePCBot`) and username.
3. Copy the Bot API Token (e.g. `7890123456:AAH...`).
4. Set the token on your PC:
   ```powershell
   setx TELEGRAM_BOT_TOKEN "7890123456:AAH..."
   ```
5. Run Homie (`.\run.bat` or `python app.py`). In the Windows tray menu, choose **Copy Telegram pairing command**, then paste the command into the bot's private chat within 15 minutes. Send `/start` after pairing to see the controls.

---

## 📞 Call Your PC from Any Phone (Duplex Voice & Remote Control)

Homie allows you to make live two-way voice telephone calls to your Windows workstation:

- 🎙️ **Direct Mobile Web Audio Call (`/call`)**: Open `http://<your-pc-ip>:5055/call` in any mobile browser on Wi-Fi. Tap the call button, speak freely to Homie, and hear synthesized vocal answers directly through your phone earpiece with zero lag.
- ☎️ **Twilio PSTN Inbound Calling (`/voice`)**: Dial a real telephone number from any landline or mobile phone. Homie picks up, says *"Homie workstation online, how can I assist you?"*, executes your requested desktop task, and replies over the phone line.
- 📱 **Wireless Trackpad & Presentation Remote (`/remote`)**: Turns your smartphone into a wireless trackpad, media controller, and presentation clicker (F5 fullscreen, slide advance, blackout screen, remote keyboard typing).
- 🧠 **Semantic Screen Memory & Recall**: Automatically indexes what you read or saw on your screen so you can ask: *"What was on my screen 15 minutes ago?"* or *"Find on screen invoice"*.
- 🔌 **Workstation MCP Server (`homie_mcp.py`)**: Exposes Homie as a Model Context Protocol server over JSON-RPC 2.0. Claude Desktop, Cursor, and IDEs can now natively query screen memory, snap windows, check vitals, and control the PC.
- ⚡ **Pipeline Latency & Observability (`pipeline_telemetry.py`)**: Precision per-stage latency tracking (STT, Router, Win32 Action, TTS) guaranteeing the sub-50ms fast-path commitment.
- 🎙️ **Voice Barge-in & Interruption**: Instant purge-on-interrupt; speaking or pressing keys immediately halts active speech synthesis.
- 🛡️ **Cryptographic Agent Audit Ledger (`agent_audit_ledger.py`)**: Immutable SHA-256 hash-chained ledger tracking every agent tool invocation, with dynamic nonce prompt-injection boundaries and elevated terminal execution gates.
- ☣️ **Session Taint Tracking & Step-Up Approval (`taint_tracker.py`)**: Taints sessions upon ingesting untrusted or sensitive data; subsequent write actions require out-of-band user approval.
- 🖥️ **Desktop Grounding Agent (`desktop_agent.py`)**: UIA-first accessibility grounding, password field blocking, emergency abort, step budgets, and dry-run preview.
- ⚡ **Workflow Compiler (`workflow_compiler.py`)**: Compiles multi-step verified agent actions into deterministic, parameterized macros running at <50ms.
- 🤖 **Chrome Claude AI Bridge**: Bi-directional loop bridge interacting directly with your active Claude AI web tab in Google Chrome for autonomous review and iterative engineering loops.

---

## 🚀 Quick Install

### Prerequisites
- **Windows 10 or Windows 11**
- **Python 3.10+** (Python 3.14+ supported)
- [Claude Code CLI](https://claude.com/claude-code) (`npm install -g @anthropic-ai/claude-code`) or a local model (Ollama, LM Studio)

### One-Click Setup
Open PowerShell in the project directory and run:

```powershell
.\install.ps1
```

Or manually install dependencies:

```powershell
pip install -r requirements.txt
```

---

## 🎮 Launching Homie

### Run the Desktop App
Double-click `run.bat` or run:

```powershell
python app.py
```

Homie opens a compact chat window and adds a **System Tray** icon. Minimize it to keep it out of the way; the global push-to-talk shortcut works while Homie remains running.

### Text-First Terminal Chat

Start a streaming text conversation using the provider configured in Homie's settings:

```powershell
python chat_cli.py
```

The terminal chat keeps conversation history in memory until you exit. It can read system vitals and list recent Downloads through Homie's ActionBroker. Those read-only results are sent to the configured model when a tool is used. Consequential tools are not exposed in this chat. Set `HOMIE_NAME` to customize the assistant name, and configure provider credentials with `GEMINI_API_KEY`, `NVIDIA_API_KEY`, or `GROQ_API_KEY` (Ollama needs no key).

The desktop app's typed asks and push-to-talk transcripts enter the same tool-aware conversation core. Transcription uses the existing local Whisper engine; replies stream into the overlay and are spoken in sentence chunks through Windows SAPI. The transcript remains visible in the overlay, and starting push-to-talk while Homie is speaking interrupts speech and cancels the current user turn. The terminal remains available as a text-only interface.

### Global Hotkeys
| Hotkey | Action |
| --- | --- |
| <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>Space</kbd> *(Hold)* | Start recording voice; release to send |
| <kbd>Esc</kbd> | Cancel active speech or stop in-progress task |
| *Click the Card* | Click an answer to copy it; click the bubble to edit and ask again |

---

## 🗣️ Things You Can Say

| You Say | What Homie Does |
| --- | --- |
| *"Chrome on the left, Notepad on the right."* | Snaps and arranges both windows instantly. |
| *"Pause music"* or *"Volume up"* | Triggers Windows media keys with 0ms delay. |
| *"Open Spotify"* or *"Launch VS Code"* | Opens the app or brings its active window forward. |
| *"What time is it?"* | Speaks or displays the current time instantly. |
| *"Find my quarterly report in Downloads."* | Searches your files and opens the match. |
| *"What's on my screen right now?"* | Takes a display capture and analyzes active content. |
| *"Search YouTube for lofi coding beats"* | Launches your default browser directly to the results. |
| *"When I say focus mode, close games and open Code."* | Remembers the shortcut to replay anytime. |

---

## 🛠️ CLI Mode

Homie also comes with a command-line interface for scripting and terminal power users:

```powershell
# Run a prompt
python homie.py "What's on my screen?"

# Capture all connected displays
python homie.py --look

# Snap foreground window
python homie.py --place "" left
python homie.py --place chrome right

# Fast DuckDuckGo search (no API key needed)
python homie.py --search "faster-whisper windows"

# Read plain text from a URL
python homie.py --read "https://news.ycombinator.com"

# Save or remove persistent rules
python homie.py --remember "Prefer concise code examples"
python homie.py --forget "concise"

# Test instant command
python homie.py --fast "pause music"
```

---

## 📁 Project Architecture

```
d:\homie\
├── app.py                 # PyWebView chat window, hotkeys, system tray
├── homie.py               # Core brain, Claude Code bridge, fast command engine, safety gate
├── windows_tools.py       # Windows native automation (win32gui, monitors, media keys, mss)
├── voice.py               # Local Whisper speech-to-text & live audio RMS visualizer
├── ui/
│   ├── chat.html          # Compact chat, transcript, voice and minimize controls
│   ├── ui.html            # Legacy floating-card interface
│   ├── orbs.js            # Legacy thinking-orbs Canvas engine
│   ├── settings.html      # Settings pane (hotkey, voice models, safe mode)
│   ├── AppIcon.ico        # Windows app icon
│   └── AppIcon.png        # Icon asset
├── tests/                 # Unit & regression test suite
│   ├── test_windows_tools.py
│   ├── test_fast_commands.py
│   ├── test_homie.py
│   └── test_voice.py
├── run.bat                # Windows batch launcher
├── install.ps1            # Automated Windows installer & shortcut creator
└── requirements.txt       # Python dependencies
```

---

## 🧪 Running Tests

To run the full regression test suite:

```powershell
python -m pytest -q
```

Pytest loads `tests/conftest.py`, which resets safety state between tests.

---

## 📜 Credits & Acknowledgments

- **Atticus for macOS**: Concept and inspiration from [Caleb Writes Code](https://youtube.com/@calebwritescode) and [SaarthurR/atticus-mac](https://github.com/SaarthurR/atticus-mac).
- **Thinking Orbs**: Canvas particle animation by [Jakub Antalik](https://github.com/Jakubantalik/thinking-orbs) (MIT).
- Built with Python, PyWebView, faster-whisper, and PyWin32.

---

## 📄 License

MIT License. Free and open source for personal and commercial use.
