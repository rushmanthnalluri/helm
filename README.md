# ⚓ Helm — Windows Desktop Assistant with Local Voice Dictation

<p align="center">
  Hold <kbd>Ctrl</kbd> <kbd>Alt</kbd> <kbd>Space</kbd>, say what you need, let go.<br>
  <b>Helm</b> transcribes caret dictation on-device and can connect to local or cloud AI providers.
</p>

<p align="center">
  <b>🧠 Durable Memory</b> &nbsp;·&nbsp; 
  <b>🎙️ Local Caret Dictation</b> &nbsp;·&nbsp;
  <b>⌨️ Unicode Keyboard Input</b> &nbsp;·&nbsp;
  <b>🛡️ Windows UI Automation</b> &nbsp;·&nbsp;
  <b>🆓 Local Ollama or Offline Mode</b> &nbsp;·&nbsp;
  <b>Free &amp; Open Source</b>
</p>

---

## 🌟 What is Helm?

**Helm** is an open-source Windows desktop assistant for Windows 10 and Windows 11. Caret dictation uses local Whisper transcription and Unicode `SendInput`; it does not use the clipboard. Helm can run in local offline mode, connect to Ollama, or send prompts and selected context to a cloud provider when one is configured.

### Core Capabilities

| Capability | Detail |
| :--- | :--- |
| **🎙️ Caret Dictation** | The desktop path uses local Whisper and Unicode keyboard input without touching the clipboard. Keep the target app focused; Helm cancels insertion if focus changes. Physical compatibility acceptance across Windows apps is still pending. |
| **🗣️ Talk to Helm** | Hold <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Space</kbd> to send speech to Helm. Transcription is local by default; optional Google speech fallback is off unless enabled in settings. |
| **⚡ Omnibar** | Press <kbd>Alt</kbd>+<kbd>Space</kbd> to open the fuzzy-search omnibar for app launching, file search, web queries, and quick commands. |
| **🎨 Interactive Side Canvas** | Side-by-side Artifacts 2.0 viewer rendering code, live diagrams (Mermaid), and formatted Markdown reports alongside your chat. |
| **🖱️ Windows UI Automation** | Uses Microsoft UI Automation (UIA) patterns such as `InvokePattern` and `ValuePattern` for supported controls. |
| **👀 Screen Vision & OCR** | *"What's on my screen right now?"* — captures display frames and analyzes open windows, active editors, or visual errors. |
| **🪟 Native Window Snapping** | *"Put Chrome on the left and VS Code on the right"* — snaps windows across multi-monitor topologies while respecting taskbar and DPI scaling. |
| **🧠 Durable Memory & Knowledge Graph** | Persistent entity extraction and SQLite-backed rules injected contextually into agent turns. |
| **🛡️ Consequential-action approvals** | The broker requests Windows Hello for medium- and high-risk actions; that route fails closed if Hello is unavailable and no explicit fallback is configured. The supervisor separately requires a signed approval from an enrolled device for protected consequential actions and denies them when no device is enrolled. Windows Hello alone does not replace that supervisor signature. |
| **⚙️ Macro & Skill Compiler** | Compiles natural-language multi-step instructions into reusable macros. Review action approvals and platform requirements before enabling automation. |

---

## 🤖 Multi-Provider AI and Offline Options

Helm can use local models or cloud providers:

| Provider | Free Tier | Supported Models |
| :--- | :--- | :--- |
| **Local Ollama** | Runs locally after Ollama and a model are installed | `qwen2.5`, `llama3.2`, `mistral`, and custom models |
| **Google AI Studio (Gemini)** | ✅ Generous free tier, multimodal vision | `gemini-2.0-flash`, `gemini-1.5-flash` |
| **Groq Cloud** | ✅ Ultra-fast Llama inference | `llama-3.3-70b-versatile` |
| **NVIDIA NIM** | ✅ Free cloud developer credits | `meta/llama-3.3-70b-instruct`, `deepseek-ai/deepseek-r1` |

### Provider and data behavior
The default provider setting is `auto`: configured cloud API keys are selected before local Ollama. If no cloud key is configured, Helm tries Ollama and then offline local guidance. To keep AI requests on-device, set `provider` to `ollama` or `local_offline` in `~/.config/helm/settings.json`. When a cloud provider is selected, Helm sends the prompt and the context included for that request to that provider. Screen-analysis requests can include captured screen content. Connected integrations send data to their target service when you invoke them.

Caret dictation and talk-to-Helm transcription use the on-device Whisper model. Helm downloads the selected model the first time it is needed; recorded speech remains local. The optional `speechCloudFallback` setting is off by default. If enabled and local Whisper cannot transcribe, Helm sends the recorded speech to Google's Speech Recognition service. That option also requires the optional `SpeechRecognition` package.

### Configuring Cloud Providers

```powershell
# Google AI Studio (best for multimodal vision):
setx GEMINI_API_KEY "AIzaSy..."

# Groq:
setx GROQ_API_KEY "gsk_..."

# NVIDIA NIM:
setx NVIDIA_API_KEY "nvapi-..."
```

Or configure directly in `~/.config/helm/settings.json`.

---

## 🚀 Quick Start

### Prerequisites
- **Windows 10 or Windows 11** (x64)
- **Python 3.12 x64** for the checked-in Windows build workflow

### Installation

```powershell
# Clone the repository
git clone https://github.com/helm-ai/helm.git
cd helm

# Install core desktop dependencies
python -m pip install -r requirements.txt

# Optional feature integrations and larger ML/TTS stacks
python -m pip install -r requirements-optional.txt
```

---

## 🎮 Launching Helm

### 1. Desktop Experience (Mica Alt UI & System Tray)

```powershell
python -m helm.gui.app
```
*Opens the desktop panel with system tray icon, local caret dictation, talk-to-Helm, Omnibar, and Side Canvas.*

### 2. Local Caret Dictation

Hold <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> in the target app, speak, and release. The desktop implementation transcribes with local Whisper and sends Unicode keyboard input without using the clipboard. The target app must stay focused; Helm cancels insertion if focus changes. On first use, Whisper downloads its model to `~/.config/helm/whisper`. Physical acceptance testing across Windows apps is pending; this code path is not yet a verified compatibility claim.

### 3. Text Terminal Chat

```powershell
python -m helm.engine.chat_cli
```
*Interactive streaming terminal session with conversation history and access to the complete tool broker.*

### 4. Direct CLI Brain

```powershell
# Ask questions directly
python -m helm.core.helm "What's on my screen?"

# Multi-monitor visual inspect
python -m helm.core.helm --look

# Snap active window
python -m helm.core.helm --place chrome left

# Test instant command
python -m helm.core.helm --fast "pause music"
```

---

## ⌨️ Global Shortcuts

| Shortcut | Action | Scope |
| :--- | :--- | :--- |
| <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> *(Hold)* | Local caret dictation | Global OS |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Space</kbd> *(Hold)* | Talk to Helm | Global OS |
| <kbd>Alt</kbd>+<kbd>Space</kbd> | Toggle the Omnibar | Global OS |
| <kbd>Esc</kbd> | Dismiss active card, barge-in speech, or cancel turn | Active Window |

---

## 📁 Modular Architecture

Helm follows a clean, modular package structure under the `helm` namespace:

```
d:\homie\
│
├── helm/
│   ├── core/                        # OS foundations & Security Subsystem
│   │   ├── helm.py                  # Core runtime engine & fast command router
│   │   ├── helm_supervisor.py       # Out-of-process isolation supervisor
│   │   ├── windows_hello.py         # Windows Hello biometric verification gate
│   │   ├── crypto_vault.py          # AES-256-GCM encrypted local store
│   │   ├── agent_audit_ledger.py    # HMAC-SHA256 hash-chained audit ledger
│   │   ├── taint_tracker.py         # Session taint tracking & step-up gates
│   │   ├── helm_confinement.py      # AppContainer sandbox isolation
│   │   ├── helm_hal.py              # Win32 hardware abstraction layer
│   │   ├── event_log.py             # Tamper-evident structured event logger
│   │   └── update_verifier.py       # Monotonic Ed25519 update verification
│   │
│   ├── gui/                         # Windows desktop interface
│   │   ├── app.py                   # Main PyWebView shell & hotkey pump
│   │   ├── helm_omnibar.py          # Spotlight/Raycast-class Omnibar overlay
│   │   ├── helm_canvas.py           # Interactive Side Canvas & Artifacts 2.0
│   │   ├── helm_style.py            # Windows 11 Mica Alt & Acrylic backdrops
│   │   └── tray_hud.py              # System tray HUD & status notifications
│   │
│   └── engine/                      # Intelligence, Dictation & Automation
│       ├── voice_inject.py          # Unicode SendInput; no clipboard use
│       ├── voice_pipeline.py        # Streaming VAD + faster-whisper STT
│       ├── windows_tools.py         # Deterministic UIA automation (Zero PyAutoGUI)
│       ├── ai_engine.py             # Multi-provider LLM router & vision analyzer
│       ├── chat_core.py             # Streaming agent core & tool execution
│       ├── helm_plugin_sdk.py       # First-class plugin SDK & discovery
│       ├── semantic_screen_memory.py# SQLite vector screen memory indexer
│       └── desktop_agent.py         # Accessibility-grounded desktop agent
│
├── packaging/                       # MSIX assets and release templates
│   ├── AppxManifest.xml             # MSIX identity and capabilities
│   └── winget/Helm.yaml             # WinGet release template
│
├── plugins/                         # Built-in & Custom Extensions
│   ├── spotify/                     # Spotify playback & queue management
│   ├── github/                      # GitHub issue and pull request tracker
│   ├── notion/                      # Notion workspace integration
│   ├── weather/                     # Local forecast service
│   └── converter/                   # Units & currency converter
│
├── ui/                              # Web Interface Assets
│   ├── chat.html                    # Compact chat window
│   ├── canvas.html                  # Side Canvas viewer
│   └── omnibar.html                 # Omnibar search overlay
│
└── tests/                           # Unit and integration tests
```

---

## 🔌 Plugin System & SDK

Helm provides a complete plugin architecture. Plugins declare a `manifest.json` and a `plugin.py` subclassing `HelmPlugin`:

```python
# plugins/my_plugin/plugin.py
from helm.engine.helm_plugin_sdk import HelmPlugin

class MyPlugin(HelmPlugin):
    name = "my_plugin"

    def on_command(self, text: str) -> bool:
        if "my custom action" in text.lower():
            # execute custom logic
            return True
        return False
```

Helm discovers plugins from `plugins/` and user configuration directories automatically on startup.

---

## 🧪 Tests

The first command runs a selected ten-file regression set. It does not run every test file or prove dictation works across physical Windows apps. The second command asks pytest to run the full `tests/` tree.

```powershell
# Selected regression files
python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q

# Run the full test tree
python -m pytest tests/ -q
```

---

## 📦 Packaging & Distribution

- **Standalone build:** `python scripts/build_standalone.py --clean` creates `dist/Helm/Helm.exe` and `dist/Helm.sha256`.
- **MSIX:** `scripts/build_msix.ps1` creates and signs a package when a publisher certificate and Windows SDK are available. Use `-SkipSign` only for local development.
- **WinGet:** `packaging/winget/Helm.yaml` is a template. The signed release workflow generates the manifest and artifact hash; this checkout does not contain a published installer.

---

## 📄 License

See [LICENSE](LICENSE).
