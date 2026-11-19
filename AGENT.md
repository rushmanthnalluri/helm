# Helm Agent Mission & Architecture Blueprint

## Mission

Build a dependable, privacy-first personal assistant with one shared agent core for text, voice, caret dictation, tools, durable memory, and proactive workflows. Keep action execution visible, deterministic, and enforce hardware-backed safety controls.

## Product Identity

The product name is **Helm**. It runs natively on Windows 10 and Windows 11 as a sovereign desktop platform.

## Engineering Principles

1. **Sub-10ms Native Responsiveness**: The desktop shell utilizes native Windows 11 Mica Alt (`DWMSBT_TABBEDWINDOW`) and Acrylic materials with pre-warmed HWND pools, maintaining a background idle footprint under **80 MB RAM** and **<0.1% CPU**.
2. **Universal Caret Dictation**: Audio is transcribed on-device via local Whisper and streamed directly into the active foreground caret via hardware-level `SendInput(KEYEVENTF_UNICODE)` with sub-300ms latency, automatic filler-word stripping (`um`, `uh`, `like`), and zero clipboard clobbering.
3. **Deterministic UI Automation**: Strictly zero `pyautogui` invocations. Desktop automation relies on deep Microsoft UI Automation (UIA) COM patterns (`InvokePattern`, `ValuePattern`), explicit window confinement checks, and deterministic polling guards.
4. **Hardware-Level Security & Biometrics**: Sensitive actions (file system writes, process spawning, credential access) are physically gated behind on-device Windows Hello biometric verification and out-of-process supervisor checks.
5. **Clean Modular Architecture**: Modular package hierarchy (`helm.core`, `helm.gui`, `helm.engine`) backed by a PEP 451 dynamic import hook (`HelmShimFinder` in `helm/__init__.py`) ensuring legacy flat imports remain backward-compatible.

## Configuration and Secrets

- Keep provider credentials in environment variables (`GEMINI_API_KEY`, `NVIDIA_API_KEY`, `GROQ_API_KEY`) or the user's settings file (`~/.config/helm/settings.yaml`). Never commit credentials.
- Zero-config mode: If no cloud API keys are present, Helm defaults to local offline inference via Ollama or local guidance fallback.
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
    ├── voice_inject.py          # Universal Caret Dictation (SendInput UNICODE)
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
- **10-Suite Regression Battery**:
  ```powershell
  python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q
  ```
- **Full Test Suite (800+ tests)**:
  ```powershell
  python -m pytest tests/ -q
  ```
