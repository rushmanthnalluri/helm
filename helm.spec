# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules


ROOT = Path(SPECPATH).resolve()
faster_whisper_datas, faster_whisper_binaries, faster_whisper_hiddenimports = collect_all("faster_whisper")
webview_datas, webview_binaries, webview_hiddenimports = collect_all("webview")

datas = [
    (str(ROOT / "ui"), "ui"),
    (str(ROOT / "plugins"), "plugins"),
    (str(ROOT / "AGENT.md"), "."),
    (str(ROOT / "LICENSE"), "."),
    *faster_whisper_datas,
    *webview_datas,
]

binaries = [*faster_whisper_binaries, *webview_binaries]
hiddenimports = [
    *collect_submodules("helm"),
    *collect_submodules("winrt"),
    *faster_whisper_hiddenimports,
    *webview_hiddenimports,
    "win32timezone",
]

a = Analysis(
    [str(ROOT / "helm" / "gui" / "app.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch",
        "torchaudio",
        "silero_vad",
        "sentence_transformers",
        "onnxruntime",
        "openpyxl",
        "lxml",
        "spotipy",
        "googleapiclient",
        "google_auth_oauthlib",
        "msal",
        "kokoro",
        "piper",
        "pyttsx3",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Helm",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "ui" / "AppIcon.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Helm",
)
