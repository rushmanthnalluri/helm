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

**Homie** is an open-source, hold-to-talk desktop voice assistant built natively for **Windows 10 and Windows 11**. 

Inspired by macOS's [Atticus](https://github.com/SaarthurR/atticus-mac) by Caleb Writes Code and SaarthurR, Homie brings the entire concept to Windows with native Windows automation, multi-display support, edge-to-edge floating acrylic UI, and local on-device speech transcription.

### Key Capabilities

- **Hold to talk**: Hold <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>Space</kbd> anywhere in Windows, speak naturally, and release to send.
- **⚡ Instant Commands ($0, <50ms)**: Window snapping, opening apps, media controls, web search, time, and system commands bypass the AI entirely and run in milliseconds.
- **👀 Screen Vision**: Ask *"What's on my screen?"* or *"Where is the save button?"* and Homie takes high-resolution display captures to inspect controls.
- **🪟 Windows Window Management**: *"Put Chrome on the left and VS Code on the right"* snaps windows across any number of monitors while respecting your taskbar.
- **🎙️ On-Device Privacy**: Uses on-device `faster-whisper` (CTranslate2 INT8) for transcription. Your audio never leaves your computer.
- **✨ Glowing Thinking Orb UI**: Features Jakub Antalik's animated thinking-orbs Canvas engine in a floating translucent card that never steals focus from what you're doing.
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

Homie will appear in your **System Tray** and float a glowing, unobtrusive acrylic card in the corner of your primary display.

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
├── app.py                 # PyWebView floating acrylic GUI, hotkeys, system tray
├── homie.py               # Core brain, Claude Code bridge, fast command engine, safety gate
├── windows_tools.py       # Windows native automation (win32gui, monitors, media keys, mss)
├── voice.py               # Local Whisper speech-to-text & live audio RMS visualizer
├── ui/
│   ├── ui.html            # Floating overlay card & reactive conversation thread
│   ├── orbs.js            # Thinking-orbs Canvas particle engine (MIT, Jakub Antalik)
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
python -m unittest discover -s tests -v
```

All 14 core tests verify window discovery, media hardware controls, instant commands, memory rule storage, search parsing, and voice level computation.

---

## 📜 Credits & Acknowledgments

- **Atticus for macOS**: Concept and inspiration from [Caleb Writes Code](https://youtube.com/@calebwritescode) and [SaarthurR/atticus-mac](https://github.com/SaarthurR/atticus-mac).
- **Thinking Orbs**: Canvas particle animation by [Jakub Antalik](https://github.com/Jakubantalik/thinking-orbs) (MIT).
- Built with Python, PyWebView, faster-whisper, and PyWin32.

---

## 📄 License

MIT License. Free and open source for personal and commercial use.
