# 🏠 Helm — The privacy-first, locally-sovereign AI assistant for Windows

<p align="center">
  Hold <kbd>Ctrl</kbd> <kbd>Alt</kbd> <kbd>Space</kbd>, say what you need, let go.<br>
  <b>Helm</b> moves your windows, reads your screen, controls your PC, and thinks for you — entirely on your hardware.
</p>

<p align="center">
  <b>🧠 Durable memory &amp; rules</b> &nbsp;·&nbsp; <b>⚡ &lt;50ms instant commands</b> &nbsp;·&nbsp; <b>🔒 On-device voice, never leaves your PC</b> &nbsp;·&nbsp; <b>🆓 Start free with Ollama — no API key needed</b> &nbsp;·&nbsp; <b>Free and open source</b>
</p>

---

## 🌟 What is Helm?

**Helm** is an open-source, privacy-first desktop AI assistant built natively for **Windows 10 and Windows 11**. It combines push-to-talk voice control, real-time screen vision, window management, anticipatory intelligence, and enterprise-grade security into a single lightweight tray application — with every piece of voice processing running 100% on your own hardware.

### Core Capabilities

| Capability | Detail |
| :--- | :--- |
| **🎙️ Push-to-talk Voice** | Hold <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> anywhere, speak naturally, release to send. Local `faster-whisper` (CTranslate2 INT8) — audio never leaves your PC. |
| **⚡ Instant Commands** | Window snapping, media keys, app launching, web search, time queries — bypass the AI entirely and run in **<50 ms**. |
| **👀 Screen Vision & OCR** | *"What's on my screen?"* — Helm takes a high-res display capture and analyzes it on the spot. |
| **🪟 Window Management** | *"Put Chrome on the left and VS Code on the right"* — snaps across any number of monitors, respects the taskbar. |
| **🧠 Durable Memory & Rules** | *"Remember to always reply in bullet points"* — stored persistently and injected into every future prompt. |
| **🔮 Anticipatory Engine** | Pre-meeting intelligence cards, end-of-day briefings, ambient desktop intent monitoring. |
| **📸 Semantic Screen Memory** | Automatically indexes what you see. Ask *"What was on my screen 15 minutes ago?"* or *"Find invoice on screen"*. |
| **🗣️ Neural TTS** | Kokoro / Piper local low-latency speech synthesis. Barge-in support — speaking immediately interrupts active reply. |
| **⚙️ Skill Compiler** | Compile natural-language descriptions into deterministic **<50 ms macros** that replay on demand. |
| **🛡️ Safe by Default** | Interactive Allow / Don't Allow card before any destructive operation (`rmdir /s`, `format`, `del /f /q`, shutdown). |

---

## 🤖 Multi-Provider AI

Helm supports four AI providers — **start completely free** with local Ollama (no account, no key, 100% offline):

| Provider | Free Tier | Supported Models |
| :--- | :--- | :--- |
| **Local Ollama** | ✅ **100% Free & Offline** (no key) | `qwen2.5`, `llama3.2`, `mistral`, and any Ollama model |
| **Google AI Studio (Gemini)** | ✅ Generous free limits, multimodal vision | `gemini-2.0-flash`, `gemini-1.5-flash` |
| **Groq Cloud** | ✅ Free tier — blazing fast Llama | `llama-3.3-70b-versatile` |
| **NVIDIA NIM** | ✅ Free API credits on signup | `meta/llama-3.3-70b-instruct`, `deepseek-ai/deepseek-r1` |

### Configuring a Provider

```powershell
# Google AI Studio (best for screen vision):
setx GEMINI_API_KEY "AIzaSy..."

# Groq:
setx GROQ_API_KEY "gsk_..."

# NVIDIA NIM:
setx NVIDIA_API_KEY "nvapi-..."

# Ollama needs no key — just run: ollama pull qwen2.5
```

Or set it in `~/.config/helm/settings.json`:

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
- A local model via **[Ollama](https://ollama.com)** *(easiest, no API key)* — or any of the cloud providers above

> [!NOTE]
> Ollama is the fastest way to get started: `ollama pull qwen2.5` and you're ready.

### One-Click Setup

```powershell
.\install.ps1
```

Or install dependencies manually:

```powershell
pip install -r requirements.txt
```

---

## 🎮 Launching Helm

### Desktop App

```powershell
python app.py
# or double-click run.bat
```

Helm opens a compact chat window and adds a **System Tray** icon. Minimize it to keep it out of the way — the global push-to-talk shortcut works wherever Helm is running.

### Text-Only Terminal Chat

```powershell
python chat_cli.py
```

Streaming text conversation using your configured provider. Keeps full conversation history in memory, can read system vitals and recent Downloads via the ActionBroker. Set `HELM_NAME` to customize the assistant name.

### Global Hotkeys

| Hotkey | Action |
| :--- | :--- |
| <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Space</kbd> *(Hold)* | Start voice recording; release to send |
| <kbd>Esc</kbd> | Cancel active speech or stop in-progress task |
| *Click the card* | Copy the answer; click the bubble to edit and ask again |

---

## 🗣️ Things You Can Say

| You Say | What Helm Does |
| :--- | :--- |
| *"Chrome on the left, Notepad on the right."* | Snaps and arranges both windows instantly. |
| *"Pause music"* / *"Volume up"* | Triggers Windows media keys — 0 ms delay. |
| *"Open Spotify"* / *"Launch VS Code"* | Opens the app or brings its window forward. |
| *"What time is it?"* | Speaks or displays the current time instantly. |
| *"Find my quarterly report in Downloads."* | Searches your files and opens the match. |
| *"What's on my screen right now?"* | Takes a display capture and analyzes active content. |
| *"Search YouTube for lofi coding beats"* | Opens your browser directly to the results. |
| *"When I say focus mode, close games and open Code."* | Compiles the shortcut to replay anytime. |
| *"What was on my screen 15 minutes ago?"* | Queries semantic screen memory index. |

---

## 🛠️ CLI Mode

```powershell
# Ask a question
python helm.py "What's on my screen?"

# Capture all connected displays
python helm.py --look

# Snap foreground window
python helm.py --place "" left
python helm.py --place chrome right

# Fast DuckDuckGo search (no key needed)
python helm.py --search "faster-whisper windows"

# Read plain text from a URL
python helm.py --read "https://news.ycombinator.com"

# Save or remove persistent rules
python helm.py --remember "Prefer concise code examples"
python helm.py --forget "concise"

# Test instant command
python helm.py --fast "pause music"
```

---

## 📱 Telegram Remote Control

Message or send voice notes to your PC from anywhere — 100% free:

- 🎙️ **Voice Walkie-Talkie**: Send a Telegram voice message; Helm transcribes it locally, executes, and replies to your phone.
- 📸 **`/screen`** — Get an instant screenshot of all your displays.
- 🔒 **`/lock`** — Lock the workstation immediately from anywhere.
- 🪟 **`/snap left`** / **`/snap right`** — Remote window management.
- 🎵 **`/media pause`** / **`/media play`** / **`/media volup`** — Media control.
- 🚀 **`/open chrome`** — Remote app launch.
- 💬 **Any text prompt** — Full AI response sent back to your phone.
- 🛡️ **Secure pairing**: New installs require a short-lived one-time pairing command from the Windows tray menu. Group chats are blocked from controlling the PC.

### Telegram Setup (60 seconds)

1. Message **`@BotFather`** on Telegram → `/newbot` → copy the token.
2. Set the token on your PC:
   ```powershell
   setx TELEGRAM_BOT_TOKEN "7890123456:AAH..."
   ```
3. Run Helm (`.\run.bat`). In the tray menu, choose **Copy Telegram pairing command**, paste it into your bot's private chat. Send `/start` after pairing.

---

## 📞 Phone Call & Remote Interfaces

| Feature | How |
| :--- | :--- |
| **Mobile Web Audio Call** | Open `http://<your-pc-ip>:5055/call` in a mobile browser on Wi-Fi. Live two-way duplex voice — speak to Helm, hear synthesized answers in your earpiece. |
| **Twilio PSTN Inbound** | Dial a real phone number. Helm picks up, executes your desktop task, replies over the phone line. |
| **Wireless Trackpad / Remote** | Open `/remote` on your phone browser — full wireless trackpad, media controller, and presentation clicker (slide advance, blackout, keyboard input). |

---

## 🔌 Integrations

### MCP Server (`helm_mcp.py`)
Exposes Helm as a **Model Context Protocol** server over JSON-RPC 2.0. Claude Desktop, Cursor, and any MCP-aware IDE can natively query screen memory, snap windows, check system vitals, and control the PC without any extra plugin.

### Mail & Calendar (`helm_mail_calendar.py`)
Read and write emails and calendar events across **Google Workspace** and **Microsoft 365**. All write operations are gated behind WebAuthn physical verification.

### Browser Automation (`helm_browser_broker.py`, `helm_cdp.py`)
CDP-based browser control with WebAuthn gating and anti-TOCTOU DOM checks before any destructive browser action.

### IDE Bridge (`helm_ide_bridge.py`)
Bi-directional bridge between Helm and your active IDE session for autonomous code review and iterative engineering loops.

---

## 🧩 Plugin System

Helm ships with a first-class plugin runtime. Drop a plugin folder into `plugins/` to extend capabilities at runtime.

**Bundled plugin:**
- `plugins/spotify/` — Spotify playback control via Spotify Web API (see `plugins/spotify/README.md`)

**Writing a plugin:**

```python
# plugins/myplugin/plugin.py
from helm_plugins import HelmPlugin

class MyPlugin(HelmPlugin):
    name = "myplugin"

    def on_command(self, text: str) -> bool:
        if "my trigger" in text.lower():
            # do something
            return True          # consumed
        return False             # pass through
```

Place `manifest.json` alongside `plugin.py` to describe the plugin's name, version, and trigger phrases. Helm's plugin loader (`helm_plugins.py`) discovers and hot-loads plugins on startup.

**Skill Compiler** (`skill_compiler.py`): Describe a workflow in natural language and Helm compiles it into a reusable, deterministic macro (<50 ms replay).

---

## 🛡️ Security Architecture

Helm was built from the ground up with a defense-in-depth security model. Key layers:

| Layer | Module | Detail |
| :--- | :--- | :--- |
| **AppContainer Sandbox** | `helm_confinement.py`, `worker_confinement.py` | Worker processes run inside AppContainer with a job-object kill switch — no escape to host process. |
| **WebAuthn Physical Gate** | `webauthn_verifier.py`, `phone_approval_portal.py` | Destructive or sensitive actions (mail write, browser automation, vault access) require physical phone verification. |
| **Cryptographic Audit Ledger** | `agent_audit_ledger.py` | Immutable SHA-256 hash-chained ledger of every agent tool invocation. Dynamic nonce prompt-injection boundaries. |
| **Session Taint Tracking** | `taint_tracker.py` | Sessions are tainted when untrusted data is ingested; subsequent write actions require out-of-band step-up approval. |
| **Step-Up Approval Gate** | `step_up_gate.py` | Multi-stage confirmation for elevated actions; integrates with WebAuthn. |
| **Crypto Vault** | `crypto_vault.py` | Encrypted local credential store with key recovery. |
| **Policy Envelopes & Rails** | `policy_envelope.py`, `rails_config.py`, `rails_audit.py` | Declarative allow/deny policy rails around every agent action. |
| **Prompt-Injection Defense** | `helm_confinement.py`, `rails_content_boundary.py` | Content boundary enforcement, credential stripping (`helm_credential_stripper.py`), SSRF prevention (`helm_ssrf.py`). |
| **Intrusion Watch** | `helm_intrusion_watch.py` | Canary monitor + adversarial red-team (`adversarial_red_team.py`) with 100% kill rate across 112 security mutations in CI. |
| **Injection Baseline Harness** | `injection_baseline_harness.py` | Automated mutation injection test harness used in the security regression suite. |
| **Trust Tiers** | `trust_tiers.py`, `client_token_auth.py` | Tiered permission model for local UI, Telegram, MCP, and phone gateway channels. |

> [!IMPORTANT]
> See [`SECURITY_NOTES.md`](SECURITY_NOTES.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full threat model and responsible-disclosure policy.

---

## 📁 Project Architecture

```
d:\homie\
│
├── 🧠 Core
│   ├── app.py                      # PyWebView chat window, hotkeys, system tray
│   ├── helm.py                    # Core brain, fast command engine, safety gate
│   ├── chat_core.py                # Shared tool-aware conversation core
│   ├── chat_cli.py                 # Text-only terminal chat interface
│   ├── ai_engine.py                # Multi-provider AI router (Gemini / Groq / NVIDIA / Ollama)
│   ├── action_broker.py            # Unified action dispatch and routing
│   ├── action_pill.py              # Allow / Don't Allow confirmation UI
│   ├── agent_tools.py              # Agent tool definitions and schema
│   ├── durable_memory.py           # Persistent memory & custom rules store
│   ├── task_manager.py             # Background task lifecycle management
│   └── helm_lazy.py               # Lazy-import bootstrapper for fast startup
│
├── 🎙️ Voice & TTS
│   ├── voice.py                    # Local Whisper STT & live RMS visualizer
│   ├── voice_pipeline.py           # STT → router → TTS pipeline orchestration
│   ├── voice_inject.py             # Voice barge-in & interrupt handling
│   ├── helm_voice_stream.py       # Streaming voice session management
│   ├── helm_tts.py                # Neural TTS (Kokoro / Piper / Windows SAPI)
│   ├── wake_word_engine.py         # Always-on wake-word detection (optional)
│   └── pipeline_telemetry.py       # Per-stage latency tracking (STT/Router/Win32/TTS)
│
├── 🖥️ UI & Desktop
│   ├── ui/chat.html                # Compact chat window, transcript, voice controls
│   ├── ui/settings.html            # Settings pane (hotkey, models, safe mode)
│   ├── tray_hud.py                 # System tray icon & HUD overlay
│   ├── helm_hud.py                # HUD rendering engine
│   ├── helm_omnibar.py            # Fuzzy search launcher overlay (Ctrl+Space)
│   ├── helm_canvas.py             # Canvas drawing layer
│   ├── helm_ghost_desktop.py      # Ghost desktop preview mode
│   └── windows_tools.py            # Win32 automation (monitors, media keys, mss)
│
├── 🔮 Anticipatory Engine & Memory
│   ├── helm_anticipatory.py       # Pre-meeting intelligence, ambient monitoring
│   ├── helm_briefing.py           # End-of-day briefing generator
│   ├── helm_briefs.py             # Morning brief & daily digest
│   ├── semantic_screen_memory.py   # Hybrid vector-search screen memory
│   ├── screen_ocr_engine.py        # OCR pipeline for semantic indexing
│   ├── helm_memory_extractor.py   # Entity & fact extraction from screen frames
│   ├── helm_context_search.py     # Semantic search across screen memory
│   ├── helm_knowledge_graph.py    # Knowledge graph over extracted entities
│   ├── focus_tracker.py            # Active window & attention tracking
│   ├── helm_focus_mode.py         # Focus mode: close distractions, open tools
│   ├── assistant_timeline.py       # Event timeline & timeline-aware queries
│   └── meeting_notes.py            # Auto meeting notes from screen/audio
│
├── 🔒 Security
│   ├── agent_audit_ledger.py       # SHA-256 hash-chained audit ledger
│   ├── taint_tracker.py            # Session taint & step-up approval
│   ├── step_up_gate.py             # Multi-stage elevation gate
│   ├── crypto_vault.py             # Encrypted local credential vault
│   ├── webauthn_verifier.py        # WebAuthn physical phone gate
│   ├── phone_approval_portal.py    # Out-of-band approval portal
│   ├── helm_confinement.py        # AppContainer sandbox enforcement
│   ├── worker_confinement.py       # Job-object kill for worker processes
│   ├── helm_structured_approval.py# Structured confirmation protocol
│   ├── policy_envelope.py          # Declarative action policy envelopes
│   ├── rails_config.py             # Policy rails configuration
│   ├── rails_audit.py              # Rails audit trail
│   ├── rails_content_boundary.py   # Prompt content boundary enforcement
│   ├── rails_confirmation.py       # Action confirmation rails
│   ├── helm_credential_stripper.py# Strip credentials from prompts/logs
│   ├── helm_ssrf.py               # SSRF prevention layer
│   ├── helm_quarantine_reader.py  # Quarantine untrusted file content
│   ├── trust_tiers.py              # Channel trust tier model
│   ├── client_token_auth.py        # Token auth for MCP / API clients
│   ├── injection_baseline_harness.py # Mutation injection test harness
│   ├── adversarial_red_team.py     # Automated adversarial testing
│   ├── helm_intrusion_watch.py    # Canary & intrusion monitor
│   ├── canary_monitor.py           # File-system canary tokens
│   └── log_redactor.py             # PII / credential log redaction
│
├── 🤖 VLA Desktop Agent
│   ├── desktop_agent.py            # UIA-first accessibility grounding agent
│   ├── helm_vla_agent.py          # VLA desktop action planner
│   ├── grounding_tools.py          # UI element grounding & tree traversal
│   ├── workflow_compiler.py        # Natural-language → <50ms macro compiler
│   ├── skill_compiler.py           # Skill DSL compiler & registry
│   └── helm_skills.py             # Skill runtime & execution
│
├── 🔌 Integrations
│   ├── helm_mcp.py                # MCP server (JSON-RPC 2.0)
│   ├── telegram_bridge.py          # Telegram bot (voice, /screen, /lock, /snap, /open, /media)
│   ├── phone_gateway.py            # Twilio PSTN inbound voice gateway
│   ├── mobile_remote.py            # Wireless trackpad / presentation remote
│   ├── helm_mail_calendar.py      # Mail & Calendar (Google + M365, WebAuthn gated)
│   ├── helm_browser_broker.py     # CDP browser automation broker
│   ├── helm_cdp.py                # Chrome DevTools Protocol bridge
│   ├── helm_ide_bridge.py         # IDE bi-directional bridge
│   ├── claude_bridge.py            # Claude Desktop / Cursor bridge
│   ├── notification_mirror.py      # Windows notification mirroring
│   └── helm_attachments.py        # File/image attachment handling
│
├── 🛠️ Tools & Utilities
│   ├── helm_everything_search.py  # Everything SDK fast file search
│   ├── helm_file_witness.py       # File system change witness
│   ├── file_indexer.py             # Semantic file indexer
│   ├── helm_netstat.py            # Network state inspector
│   ├── helm_resource_tracker.py   # CPU/memory/disk resource tracking
│   ├── helm_hardware_profiler.py  # Hardware capability profiling
│   ├── helm_apps_catalog.py       # Installed app catalog & fuzzy match
│   ├── helm_layout_profiles.py    # Saved window layout profiles
│   ├── quick_notes.py              # Quick sticky-note capture
│   ├── reminder_scheduler.py       # In-process reminder scheduler
│   ├── clipboard_classifier.py     # Clipboard content classifier
│   ├── db_utils.py                 # Shared SQLite helpers
│   └── event_log.py                # Structured event log
│
├── 🏃 Runtime & Distribution
│   ├── helm_supervisor.py         # Background supervisor daemon
│   ├── helm_supervisor_daemon.py  # Daemon process manager
│   ├── helm_watchdog.py           # Health watchdog & auto-restart
│   ├── helm_selfheal.py           # Self-healing recovery logic
│   ├── helm_updater.py            # Velopack auto-updater (Ed25519-signed)
│   ├── update_verifier.py          # Monotonic rollback protection
│   ├── heartbeat_service.py        # Heartbeat lease service
│   ├── heartbeat_lease.py          # Lease acquisition & renewal
│   ├── key_recovery.py             # Vault key recovery flow
│   ├── kill_switch.py              # Emergency kill switch
│   ├── helm_session_compression.py# Long-session context compression
│   ├── helm_retrospective.py      # Session retrospective & learning
│   ├── startup_bench.py            # Startup latency benchmark
│   ├── shadow_mode.py              # Shadow / dry-run execution mode
│   ├── presence_monitor.py         # User presence detection
│   ├── device_registry.py          # Registered device management
│   ├── install.ps1                 # Automated Windows installer
│   ├── run.bat                     # Windows batch launcher
│   ├── helm.spec                  # PyInstaller spec
│   ├── packaging/                  # MSIX, Inno Setup, WinGet manifests
│   └── requirements.txt            # Python dependencies
│
├── 🧩 Plugins
│   ├── helm_plugins.py            # Plugin loader & runtime
│   └── plugins/spotify/            # Spotify Web API plugin
│
└── 🧪 Tests (90+ files)
    └── tests/                      # Security, voice, UI, tools, red-team, mutation testing
```

---

## 🧪 Running Tests

Helm has a comprehensive test suite — **90+ test files** covering security hardening, voice pipeline, UI integration, tools, red-team adversarial scenarios, and mutation injection:

```powershell
python -m pytest -q
```

`tests/conftest.py` resets safety state between tests. Key test areas:

- **Security** — `test_batch29`–`test_batch43_security_hardening.py`, `test_confinement_attacks.py`, `test_injection_baseline_harness.py`, `test_tier_a_adversarial.py`, `test_semantic_red_team.py`, `test_model_level_red_team.py`, `test_fuzz_guardrails.py`
- **Voice** — `test_voice.py`, `test_voice_pipeline.py`, `test_wake_word_engine.py`, `test_helm_tts.py`
- **Desktop Agent / VLA** — `test_desktop_agent_evals.py`, `test_grounding_tools.py`, `test_skill_compiler_and_recovery.py`, `test_omnibar_wiring.py`
- **Integrations** — `test_mail_calendar.py`, `test_telegram_bridge.py`, `test_webauthn_verifier.py`, `test_browser_broker.py`, `test_hardened_phone_gateway.py`
- **Core** — `test_helm.py`, `test_fast_commands.py`, `test_windows_tools.py`, `test_durable_memory.py`, `test_chat_core.py`

---

## 🗺️ Roadmap

| Direction | Detail |
| :--- | :--- |
| **Cross-device sync** | Sync memory, rules, and layout profiles across multiple Windows PCs via encrypted relay. |
| **Real-time streaming voice** | Continuous voice mode (always-listening VAD) with sub-200 ms round-trip end-to-end. |
| **macOS port** | Bring Helm's core voice + window management to macOS using Accessibility APIs. |
| **Plugin marketplace** | Signed community plugin registry — discover and install Helm plugins in one click. |
| **Workflow engine** | Visual drag-and-drop pipeline builder that compiles to the skill compiler's macro format. |

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository and create a feature branch.
2. Run the test suite to establish a baseline:
   ```powershell
   python -m pytest -q
   ```
3. Make your changes. Add or update tests for any new behaviour.
4. Ensure all tests pass before opening a pull request.
5. Open a PR with a clear description of the problem and solution.

> [!TIP]
> Check [`AGENT.md`](AGENT.md) for architecture notes aimed at AI coding agents contributing to this codebase.

Areas especially welcoming contributions: new plugins, additional language/TTS support, macOS groundwork, and documentation.

---

## 📜 Credits & Acknowledgments

- **Atticus for macOS**: Concept and original inspiration from [Caleb Writes Code](https://youtube.com/@calebwritescode) and [SaarthurR/atticus-mac](https://github.com/SaarthurR/atticus-mac). Helm is an independent Windows-native reimplementation.
- **Thinking Orbs**: Canvas particle animation by [Jakub Antalik](https://github.com/Jakubantalik/thinking-orbs) (MIT).
- Built with Python, PyWebView, faster-whisper, and PyWin32.

---

## 📄 License

MIT License — free and open source for personal and commercial use.
