# -*- mode: python ; coding: utf-8 -*-
"""homie.spec - PyInstaller Build Specification for Homie Desktop Assistant.

Configures PyInstaller to produce a production-grade Windows standalone distribution:
- Entry point: app.py (Floating Card HUD, Omnibar, Voice Pipeline & Agent Core)
- Packages UI assets (HTML/JS/CSS/Icons) and runtime configuration
- Resolves all hidden imports for pywebview, faster-whisper, winrt, cryptography, pyaudio, and pynput
- Embeds Windows application icon (ui/AppIcon.ico)
- Configures windowed (console=False) execution to prevent CMD popups
"""

import sys
import os
from pathlib import Path

# Resolve base directories
SPECPATH_DIR = Path(SPECPATH).resolve()
BASE_DIR = str(SPECPATH_DIR)

# Assets to bundle with the binary
datas = []
ui_dir = SPECPATH_DIR / "ui"
if ui_dir.is_dir():
    datas.append((str(ui_dir), "ui"))

config_dir = SPECPATH_DIR / "config"
if config_dir.is_dir():
    datas.append((str(config_dir), "config"))

# Data directory templates if present
data_dir = SPECPATH_DIR / "data"
if data_dir.is_dir():
    for sample in data_dir.glob("*.json"):
        datas.append((str(sample), "data"))

# App icon path
icon_path = str(ui_dir / "AppIcon.ico") if (ui_dir / "AppIcon.ico").exists() else None

# Runtime hooks
runtime_hooks = []
rth_hook = SPECPATH_DIR / "scripts" / "pyi_rth_homie.py"
if rth_hook.exists():
    runtime_hooks.append(str(rth_hook))

hidden_imports = [
    # --- GUI & Webview Engine ---
    "webview",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "clr",
    "pythonnet",
    "pystray",
    "pystray._win32",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",

    # --- Audio, Speech & Voice Pipeline ---
    "faster_whisper",
    "ctranslate2",
    "tokenizers",
    "huggingface_hub",
    "sounddevice",
    "_sounddevice_data",
    "soundfile",
    "speech_recognition",
    "pyaudio",
    "pyaudiowpatch",
    "numpy",

    # --- Windows API & Subsystem Automation ---
    "win32gui",
    "win32con",
    "win32api",
    "win32process",
    "win32security",
    "win32event",
    "win32pipe",
    "win32file",
    "win32ts",
    "win32clipboard",
    "win32com",
    "win32com.client",
    "win32com.shell",
    "pywintypes",
    "pythoncom",
    "pynput",
    "pynput.keyboard._win32",
    "pynput.mouse._win32",
    "pyautogui",
    "pyperclip",
    "psutil",
    "mss",
    "mss.windows",
    "uiautomation",

    # --- Windows Runtime (WinRT) ---
    "winrt",
    "winrt.system",
    "winrt.windows.ui.notifications",
    "winrt.windows.ui.notifications.management",
    "winrt.windows.applicationmodel",
    "winrt.windows.foundation",
    "winrt.windows.foundation.collections",
    "winrt.windows.storage.streams",
    "winrt.windows.media.ocr",
    "winrt.windows.graphics.imaging",
    "winrt.windows.globalization",

    # --- Security & Cryptography ---
    "cryptography",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.backends.openssl",
    "Crypto",
    "Crypto.PublicKey.ECC",
    "Crypto.Signature.eddsa",

    # --- Networking & Transports ---
    "requests",
    "urllib3",

    # --- Homie Engines & Core Modules ---
    "homie",
    "homie_supervisor",
    "action_broker",
    "agent_tools",
    "ai_engine",
    "homie_omnibar",
    "homie_ghost_desktop",
    "homie_writer",
    "homie_attachments",
    "homie_watchers",
    "homie_selfheal",
    "homie_learn",
    "homie_knowledge_graph",
    "homie_anticipatory",
    "homie_plugins",
    "homie_intrusion_watch",
    "homie_apps_catalog",
    "homie_style",
    "homie_briefs",
    "homie_snapshot",
    "meeting_notes",
    "durable_memory",
    "voice",
    "homie_voice_stream",
    "homie_vla_agent",
    "homie_canvas",
    "homie_everything_search",
    "homie_ide_bridge",
    "db_utils",
    "event_log",
    "rails_config",
    "rails_confirmation",
    "step_up_gate",
    "trust_tiers",
    "update_verifier",
    "screen_ocr_engine",
    "semantic_screen_memory",
    "notification_mirror",
    "tray_hud",
    "wake_word_engine",
    "windows_tools",
    "worker_confinement",
    "chat_cli",
    "chat_core",
    "task_manager",
    "assistant_timeline",
    "grounding_tools",
    "action_pill",
    "phone_gateway",
    "phone_approval_portal",
    "mobile_remote",
    "voice_pipeline",
    "homie_mcp",
    "homie_session_compression",
    "homie_ssrf",
    "homie_supervisor_daemon",
    "homie_focus_mode",
    "homie_layout_profiles",
    "homie_netstat",
    "homie_resource_tracker",
    "homie_retrospective",
    "homie_skills",
    "homie_worker"
]

a = Analysis(
    [os.path.join(BASE_DIR, "app.py")],
    pathex=[BASE_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=runtime_hooks,
    excludes=[
        "tkinter",
        "matplotlib",
        "pandas",
        "IPython",
        "jupyter",
        "pytest",
        "unittest"
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Homie",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="Homie",
)
