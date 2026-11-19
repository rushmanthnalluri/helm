# ⚓ Helm — The Privacy-First, Locally-Sovereign AI Assistant for Windows

<p align="center">
  Hold <kbd>Ctrl</kbd> <kbd>Alt</kbd> <kbd>Space</kbd>, say what you need, let go.<br>
  <b>Helm</b> streams text into your active caret, controls Windows, analyzes your screen, and automates tasks — entirely on your hardware.
</p>

<p align="center">
  <b>🧠 Durable Memory</b> &nbsp;·&nbsp; 
  <b>🎙️ Universal Caret Dictation</b> &nbsp;·&nbsp; 
  <b>⚡ &lt;10ms Native UI &amp; Omnibar</b> &nbsp;·&nbsp; 
  <b>🛡️ Deterministic UI Automation (Zero PyAutoGUI)</b> &nbsp;·&nbsp; 
  <b>🆓 Local Offline Fallback (Ollama)</b> &nbsp;·&nbsp; 
  <b>Free &amp; Open Source</b>
</p>

---

## 🌟 What is Helm?

**Helm** is an open-source, privacy-first desktop platform built natively for **Windows 10 and Windows 11**. It bridges hardware-level caret dictation, deterministic Microsoft UI Automation (UIA), high-resolution screen vision, and modular agent tools into a unified, high-performance desktop experience.

Whether streaming dictated prose directly into your IDE, snapping windows across multi-monitor setups, or compiling complex desktop workflows into instantaneous macros, Helm executes with sub-millisecond dispatch and a background memory footprint under **80 MB RAM**.

### Core Capabilities

| Capability | Detail |
| :--- | :--- |
| **🎙️ Universal Caret Dictation** | Hold <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> anywhere to stream voice directly into the active foreground caret via hardware-level `SendInput(KEYEVENTF_UNICODE)`. Sub-300ms latency, automatic filler-word stripping (`um`, `uh`, `like`), and zero clipboard pollution. |
| **⚡ Spotlight-Class Omnibar** | Press <kbd>Alt</kbd>+<kbd>Space</kbd> to launch the fuzzy-search omnibar for instant app launching, file search, web queries, and quick commands (<10ms activation). |
| **🎨 Interactive Side Canvas** | Side-by-side Artifacts 2.0 viewer rendering code, live diagrams (Mermaid), and formatted Markdown reports alongside your chat. |
| **🖱️ Deterministic UI Automation** | 100% PyAutoGUI-free. Deep Microsoft UI Automation (UIA) COM patterns (`InvokePattern`, `ValuePattern`) with strict window confinement boundaries and zero blind sleeps. |
| **👀 Screen Vision & OCR** | *"What's on my screen right now?"* — captures display frames and analyzes open windows, active editors, or visual errors. |
| **🪟 Native Window Snapping** | *"Put Chrome on the left and VS Code on the right"* — snaps windows across multi-monitor topologies while respecting taskbar and DPI scaling. |
| **🧠 Durable Memory & Knowledge Graph** | Persistent entity extraction and SQLite-backed rules injected contextually into agent turns. |
| **🛡️ Windows Hello Biometric Security** | Sensitive actions (credential retrieval, system modification) are physically gated behind on-device Windows Hello face/fingerprint authentication. |
| **⚙️ Macro & Skill Compiler** | Compiles natural-language multi-step instructions into deterministic, high-speed macros (<50ms execution). |

---

## 🤖 Multi-Provider AI & Zero-Config Mode

Helm supports cloud intelligence and 100% offline local inference:

| Provider | Free Tier | Supported Models |
| :--- | :--- | :--- |
| **Local Ollama** | ✅ **100% Free & Offline** (zero config) | `qwen2.5`, `llama3.2`, `mistral`, and custom models |
| **Google AI Studio (Gemini)** | ✅ Generous free tier, multimodal vision | `gemini-2.0-flash`, `gemini-1.5-flash` |
| **Groq Cloud** | ✅ Ultra-fast Llama inference | `llama-3.3-70b-versatile` |
| **NVIDIA NIM** | ✅ Free cloud developer credits | `meta/llama-3.3-70b-instruct`, `deepseek-ai/deepseek-r1` |

### Zero-Config Offline Fallback
If no API keys are configured, Helm detects local Ollama automatically. If Ollama is unavailable, Helm gracefully operates in offline local guidance mode — ensuring the app never fails on first launch.

### Configuring Cloud Providers

```powershell
# Google AI Studio (best for multimodal vision):
setx GEMINI_API_KEY "AIzaSy..."

# Groq:
setx GROQ_API_KEY "gsk_..."

# NVIDIA NIM:
setx NVIDIA_API_KEY "nvapi-..."
```

Or configure directly in `~/.config/helm/settings.yaml`.

---

## 🚀 Quick Start

### Prerequisites
- **Windows 10 or Windows 11** (x64)
- **Python 3.10+** (Python 3.11 – 3.14 fully supported)

### Installation

```powershell
# Clone the repository
git clone https://github.com/helm-ai/helm.git
cd helm

# Install production dependencies
pip install -r requirements.txt
```

---

## 🎮 Launching Helm

### 1. Desktop Experience (Mica Alt UI & System Tray)

```powershell
python -m helm.gui.app
```
*Opens the Windows 11 chat panel with system tray icon, global push-to-talk hotkey, Omnibar (<kbd>Alt</kbd>+<kbd>Space</kbd>), and Interactive Side Canvas.*

### 2. Universal Caret Dictation

Hold <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> in **any application** (VS Code, Word, Chrome, Slack, Windows Terminal), speak, and release. Helm transcribes on-device with Whisper and streams the text directly into the caret.

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
| <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> *(Hold)* | Push-to-Talk Universal Caret Dictation | Global OS |
| <kbd>Alt</kbd>+<kbd>Space</kbd> | Toggle Spotlight/Raycast Omnibar | Global OS |
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
│   ├── gui/                         # Native Windows 11 Desktop Interface
│   │   ├── app.py                   # Main PyWebView shell & hotkey pump
│   │   ├── helm_omnibar.py          # Spotlight/Raycast-class Omnibar overlay
│   │   ├── helm_canvas.py           # Interactive Side Canvas & Artifacts 2.0
│   │   ├── helm_style.py            # Windows 11 Mica Alt & Acrylic backdrops
│   │   └── tray_hud.py              # System tray HUD & status notifications
│   │
│   └── engine/                      # Intelligence, Dictation & Automation
│       ├── voice_inject.py          # Universal Caret Dictation (SendInput UNICODE)
│       ├── voice_pipeline.py        # Streaming VAD + faster-whisper STT
│       ├── windows_tools.py         # Deterministic UIA automation (Zero PyAutoGUI)
│       ├── ai_engine.py             # Multi-provider LLM router & vision analyzer
│       ├── chat_core.py             # Streaming agent core & tool execution
│       ├── helm_plugin_sdk.py       # First-class plugin SDK & discovery
│       ├── semantic_screen_memory.py# SQLite vector screen memory indexer
│       └── desktop_agent.py         # Accessibility-grounded desktop agent
│
├── packaging/                       # Production Distribution Pipeline
│   ├── AppxManifest.xml             # Signed MSIX package manifest
│   └── winget/Helm.yaml             # Authenticated WinGet package manifest
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
└── tests/                           # Complete Verification Battery (800+ tests)
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

## 🧪 Running the Verification Battery

Helm is backed by an automated verification suite covering security invariants, caret dictation, deterministic UIA, and sub-10ms UI latency:

```powershell
# Run the 10-suite production regression battery
python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q

# Run all 800+ unit, integration, and security tests
python -m pytest tests/ -q
```

---

## 📦 Packaging & Distribution

- **MSIX:** Automated build via `scripts/build_msix.ps1`.
- **WinGet:** Installable via the official manifest [`packaging/winget/Helm.yaml`](packaging/winget/Helm.yaml).
- **Auto-Updates:** Verified monotonic delta updates signed with publisher Ed25519 keys via Velopack.

---

## 📄 License

MIT License — free and open source for personal and commercial use.
