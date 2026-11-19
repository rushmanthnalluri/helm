# 🤝 Contributing to Helm

Thank you for your interest in contributing to **Helm** — an open-source Windows desktop AI assistant built with Python. Whether you're squashing bugs, dreaming up features, or improving docs, every contribution makes Helm faster, safer, and more useful for everyone. We're glad you're here! 🎉

---

## 🌟 Ways to Contribute

- 🐛 **Bug Reports** — Found something broken? Open an issue with clear reproduction steps, your OS version, and relevant logs.
- 💡 **Feature Requests** — Have an idea that would make Helm better? Open a discussion or issue describing the problem you're solving and your proposed approach.
- 🔌 **Plugins** — Extend Helm's capabilities by writing a new plugin. See [Adding a Plugin](#-adding-a-plugin) below.
- 📝 **Documentation** — Improve README files, add docstrings, write guides, or fix typos.
- 🔬 **Tests** — Add test coverage for untested paths, edge cases, or performance benchmarks.

---

## 🛠 Development Setup

### Prerequisites

- **Windows 10 or Windows 11** (required — Helm uses Windows-native APIs: UIA, DWM, Win32)
- **Python 3.10 or later** (Python 3.11 – 3.14 fully supported)
- **Git**

### Getting Started

```powershell
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-username>/helm.git
cd helm

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install production & testing dependencies
pip install -r requirements.txt

# 4. Launch the desktop GUI
python -m helm.gui.app

# 5. Or run the CLI brain
python -m helm.core.helm

# 6. Or launch the terminal chat interface
python -m helm.engine.chat_cli
```

> [!NOTE]
> Configuration lives at `%USERPROFILE%\.config\helm\settings.yaml`. You can also override settings via environment variables (`GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`).

---

## 🧪 Running Tests

Helm is verified by **800+ automated tests across 90+ test files**.

### Run the Core Production Battery

```powershell
python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q
```

### Run the Complete Test Suite

```powershell
python -m pytest tests/ -q
```

### Run a Focused Subset

```powershell
# Run a specific test file
python -m pytest tests/test_caret_dictation.py -q

# Run tests matching a keyword
python -m pytest -k "windows_hello" -q

# Run with verbose output
python -m pytest -v
```

### What the Tests Cover

| Area | Description |
|---|---|
| **Performance Benchmarks** | Sub-10ms Mica Alt compositing, HWND pre-warm latency, <80MB RAM daemon footprint |
| **Deterministic UIA** | 100% PyAutoGUI purge check (AST visitor), Microsoft UIA COM patterns, window confinement |
| **Caret Dictation** | Native `SendInput(KEYEVENTF_UNICODE)` streaming, filler word removal, sub-300ms latency |
| **Biometrics & Security** | Windows Hello face/fingerprint authentication, HMAC-SHA256 audit ledger, taint tracking |
| **Zero-Config Fallback** | Automated offline guidance and local Ollama detection |
| **Voice Pipeline** | Streaming VAD, faster-whisper STT, neural TTS barge-in |
| **Plugin Ecosystem** | Plugin discovery, manifest validation, SDK lifecycle |
| **MSIX Packaging** | AppxManifest compliance, asset enumeration, authentic WinGet SHA-256 digest |

---

## 🔒 Security-Critical Modules

The following modules implement core trust and safety mechanisms. Any pull request touching these files must ensure all security invariants remain intact:

| Module | Purpose |
|---|---|
| `helm/core/windows_hello.py` | On-device Windows Hello biometric verification gate |
| `helm/core/helm_confinement.py` | Main process sandboxing and confinement boundaries |
| `helm/core/helm_supervisor.py` | Out-of-process supervisor daemon & job confinement |
| `helm/core/taint_tracker.py` | Session taint tracking & step-up approval routing |
| `helm/core/agent_audit_ledger.py` | Tamper-evident HMAC-SHA256 action audit log |
| `helm/core/crypto_vault.py` | AES-256-GCM secret storage and key management |
| `helm/core/update_verifier.py` | Monotonic Ed25519 signed update verification |

---

## 🔌 Adding a Plugin

Helm's plugin system lives in `plugins/` and is managed by `helm.engine.helm_plugin_sdk`:

```
plugins/
└── spotify/
    ├── manifest.json   ← plugin metadata and capability declarations
    └── plugin.py       ← plugin implementation subclassing HelmPlugin
```

Declare all permissions and intent triggers in `manifest.json`.

---

## 💬 Commit Message Style

We follow **[Conventional Commits](https://www.conventionalcommits.org/)**:

```
<type>(<scope>): <summary>

[optional body]
```

**Common Types:** `feat:`, `fix:`, `docs:`, `test:`, `security:`, `refactor:`, `chore:`, `perf:`.

**Examples:**
```
feat(dictation): add filler-word filter for streaming whisper
fix(biometrics): verify Windows Hello availability before challenge
docs(readme): update package structure to helm.core, helm.gui, helm.engine
```

---

## 📄 License

Helm is released under the **MIT License**.
