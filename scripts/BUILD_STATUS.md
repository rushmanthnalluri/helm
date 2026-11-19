# Helm Standalone Binary Build Status

**Date:** 2026-11-17  
**Status:** SUCCESS (Both Standalone Distribution and Onefile Binary Built & Verified)

---

## 1. Environment & Build Tooling
- **OS:** Windows 11 (10.0.26300) x64
- **Python Version:** 3.14.5
- **PyInstaller:** 6.22.3 (contrib hooks: 2026.10)
- **Spec File:** `d:\helm\helm.spec`
- **Build Script:** `d:\helm\scripts\build_standalone.py`

---

## 2. Generated Executables & Artifacts

### A. Production Standalone Distribution (Onedir)
- **Binary Path:** `d:\helm\dist\Helm\Helm.exe`
- **Binary Size:** 20,228,267 bytes (~19.29 MB)
- **Total Distribution Directory Size:** ~352.7 MB
- **Bundled Contents:**
  - `Helm.exe`: Application bootloader and entry point (`console=False`, windowed)
  - `_internal\`: All bundled dynamic libraries (Python runtime DLL, OpenSSL, NumPy, ctranslate2, sounddevice, PyAudio, WinRT, cryptography, etc.)
  - `ui\`: Frontend HTML, CSS, JS templates (`chat.html`, `omnibar.html`, `canvas.html`, `AppIcon.ico`)
  - `config\`: Default application configuration
  - `VERSION`: "Helm Desktop AI 1.0.0 (Standalone x64)"

### B. Single-File Standalone Executable (Onefile Console)
- **Binary Path:** `d:\helm\dist\HelmTest.exe`
- **Binary Size:** 289,917,353 bytes (~276.49 MB)
- **Configuration:** Fully self-contained single-file binary with console output for diagnostic and troubleshooting runs.

---

## 3. Verification & Validation
- **Asset Verification:** All critical entry points (`app.py`, `helm.py`) and UI assets (`ui/chat.html`, `ui/omnibar.html`, `ui/canvas.html`, `ui/AppIcon.ico`) verified present.
- **Dependency Audit:**
  - `webview` (pywebview UI renderer) - Present & bundled
  - `faster_whisper` (Voice STT) - Present & bundled
  - `cryptography` (Security vault) - Present & bundled
  - `pynput` (Global hotkey listener) - Present & bundled
  - `sounddevice` (Audio I/O) - Present & bundled
  - `pystray` (System tray integration) - Present & bundled
- **Execution Test:**
  `& "d:\helm\dist\HelmTest.exe" --help` executed with return code 0, emitting standard CLI usage without import errors, missing DLL warnings, or runtime faults.

---

## 4. How to Run

### Running the Production App:
Double click or run from terminal:
```powershell
& "d:\helm\dist\Helm\Helm.exe"
```

### Running the Diagnostic Onefile Binary:
```powershell
& "d:\helm\dist\HelmTest.exe" --help
```
Or launch with custom supervisor pipe:
```powershell
& "d:\helm\dist\Helm\Helm.exe" --supervisor-pipe \\.\pipe\helm_supervisor
```
