# Helm Agent Mission & Architecture Blueprint

## Mission

Build a dependable, local-first personal assistant with one shared agent core for text, voice, caret dictation, tools, memory, and workflows. Describe shipped behavior from the active code paths; treat performance and security goals as targets until measured.

## Product Identity

The product name is **Helm**. The desktop app targets Windows 10 and Windows 11. It supports local paths and optional cloud providers; do not describe all app data paths as local-only.

## Engineering Principles

1. **Responsive Windows Desktop**: The desktop shell uses Windows APIs and a webview interface. Publish timing or memory figures only with a repeatable measurement method and results.
2. **Caret Dictation**: `Ctrl+Alt+Space` captures audio, transcribes with local Whisper, filters common fillers, and inserts Unicode `SendInput` events without using the clipboard. Keep the original target window focused; focus changes cancel insertion. Do not describe `SendInput` as hardware input.
3. **Deterministic UI Automation**: Strictly zero `pyautogui` invocations. Desktop automation relies on deep Microsoft UI Automation (UIA) COM patterns (`InvokePattern`, `ValuePattern`), explicit window confinement checks, and deterministic polling guards.
4. **Route-Specific Action Approval**: The broker requests Windows Hello for medium- and high-risk actions and fails closed when Hello is unavailable unless an explicit fallback approver is configured. Supervisor-protected consequential actions separately require a signed approval from an enrolled device; the supervisor denies them when no device is enrolled. Do not claim that every sensitive action uses Windows Hello or that Hello replaces the supervisor signature.
5. **Clean Modular Architecture**: Modular package hierarchy (`helm.core`, `helm.gui`, `helm.engine`) backed by a PEP 451 dynamic import hook (`HelmShimFinder` in `helm/__init__.py`) ensuring legacy flat imports remain backward-compatible.

## Configuration and Secrets

- Keep provider credentials in environment variables (`GEMINI_API_KEY`, `NVIDIA_API_KEY`, `GROQ_API_KEY`) or the user's settings file (`~/.config/helm/settings.json`). Never commit credentials or user databases.
- Provider routing: `auto` can select a configured cloud provider; without cloud keys it tries local Ollama, then offline guidance. Describe the selected provider and data flow accurately.
- Local cryptographic state (`.helm_vault.key`, device keys, databases) is strictly git-ignored.

## Codebase Organization

```
helm/
├── core/
│   ├── helm.py                  # Core brain, fast command router, CLI entry point
│   ├── helm_supervisor.py       # Out-of-process supervisor daemon & job confinement
│   ├── windows_hello.py         # On-device Windows Hello biometric gate
│   ├── crypto_vault.py          # AES-256-GCM encrypted local store
│   ├── agent_audit_ledger.py    # HMAC-SHA256 hash-chained audit ledger
│   ├── taint_tracker.py         # Session taint tracking & step-up gates
│   ├── helm_hal.py              # Win32 hardware abstraction layer
│   └── update_verifier.py       # Monotonic Ed25519 publisher update verification
│
├── gui/
│   ├── app.py                   # PyWebView desktop interface & Win32 hotkey loop
│   ├── helm_omnibar.py          # Spotlight/Raycast-class Omnibar launcher
│   ├── helm_canvas.py           # Interactive Side Canvas & Artifacts 2.0
│   └── tray_hud.py              # System tray HUD & status notifications
│
└── engine/
    ├── voice_inject.py          # Unicode caret input via SendInput; app acceptance is pending
    ├── voice_pipeline.py        # Streaming VAD + faster-whisper STT
    ├── windows_tools.py         # Deterministic UIA automation (Zero PyAutoGUI)
    ├── ai_engine.py             # Multi-provider LLM router & vision analyzer
    ├── chat_core.py             # Streaming agent core & tool execution
    ├── helm_plugin_sdk.py       # First-class plugin SDK & discovery
    └── desktop_agent.py         # Accessibility-grounded desktop agent
```

## Running & Testing

- **Desktop Shell**: `python -m helm.gui.app`
- **CLI Chat**: `python -m helm.engine.chat_cli`
- **Direct CLI Brain**: `python -m helm.core.helm`
- **Selected 10-File Regression Set** (not the full suite):
  ```powershell
  python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q
  ```
- **Full Test Tree**:
  ```powershell
  python -m pytest tests/ -q
  ```
