# Homie Distribution & Release Engineering Guide

This guide documents the standalone release engineering, packaging, and distribution architecture for the **Homie Windows Desktop Assistant**.

---

## 1. Distribution Architecture Overview

Homie provides two primary distribution channels for Windows 10/11 x64 systems:

| Distribution Channel | Target Artifact | Target Audience & Use Case |
|---|---|---|
| **Windows Installer** | `Homie-Setup-<version>.exe` | Primary end-user distribution. Installs Start Menu shortcuts, Desktop shortcuts, `homie://` custom protocol handler, App Paths, and uninstaller. Supports silent enterprise rollout. |
| **Portable Zip Archive** | `Homie-Windows-x64-portable-v<version>.zip` | Developers, portable USB installations, and testing environments. Includes `.bat` and silent `.vbs` launchers with a 1-click PowerShell desktop shortcut creator. |
| **Standalone Folder (PyInstaller)** | `dist/Homie/Homie.exe` | Compiled onedir distribution bundling the Python runtime, PyWebView Chromium runtime, Faster-Whisper, WinRT, and Cryptography. |
| **Verified Signed Updates** | `homie_update_manifest.json` | Incremental cryptographic auto-update system protected by Ed25519 digital signatures and monotonic epoch rollback counters. |

---

## 2. Packaging Toolchain & CLI Reference

Homie includes automated release engineering scripts under `scripts/`.

### 2.1 The Unified Packager: `scripts/package_homie.py`

The main entry point for building release artifacts.

```powershell
# Build everything (standalone binary + Inno Setup installer + portable zip)
python scripts/package_homie.py --all --version 1.0.0

# Build portable zip bundle only
python scripts/package_homie.py --portable --version 1.0.0

# Compile standalone PyInstaller binary only
python scripts/package_homie.py --standalone

# Compile Inno Setup installer only
python scripts/package_homie.py --installer --version 1.0.0

# Clean build and dist caches prior to building
python scripts/package_homie.py --all --clean
```

### 2.2 Standalone Binary Compiler: `scripts/build_standalone.py`

Orchestrates PyInstaller compilation against `homie.spec`.

```powershell
# Run a pre-flight dry run to audit assets and dependencies
python scripts/build_standalone.py --dry-run

# Automatically install PyInstaller and compile standalone executable
python scripts/build_standalone.py --install-deps --clean

# Compile with a specific spec file and version tag
python scripts/build_standalone.py --spec homie.spec --version 1.0.0
```

### 2.3 PyInstaller Specification: `homie.spec`

The declarative PyInstaller configuration:
- **Entry Point**: `app.py` (Desktop HUD, Floating Omnibar, Voice Pipeline & Agent Core).
- **Console Mode**: `console=False` (suppresses black CMD window popups; native desktop GUI).
- **Bundled Assets**: `ui/` (HTML/CSS/JS/Icons) and `config/` (MCP catalogs).
- **Runtime Hook**: `scripts/pyi_rth_homie.py` configures paths and UTF-8 console output.
- **Hidden Imports**:
  - `webview`, `webview.platforms.winforms`, `webview.platforms.edgechromium`, `clr`, `pythonnet`
  - `faster_whisper`, `ctranslate2`, `tokenizers`, `sounddevice`, `pyaudio`, `pyaudiowpatch`
  - `winrt`, `winrt.windows.ui.notifications`, `winrt.windows.media.ocr`
  - `cryptography`, `Crypto`
  - `pynput`, `pyautogui`, `pystray`, `win32gui`, `win32api`, `mss`

---

## 3. Inno Setup Installer: `scripts/homie_installer.iss`

The Inno Setup script compiles a single-file Windows setup wizard (`Homie-Setup-1.0.0.exe`).

### Key Installer Capabilities:
1. **Dynamic Payload Fallback**:
   - If `dist/Homie/Homie.exe` has been compiled, it packages the standalone binary distribution.
   - If not yet compiled to a standalone binary, it seamlessly packages the source tree and configures shortcuts to target `run.bat`.
2. **Dual-Scope Installation**:
   - Defaults to `PrivilegesRequired=lowest` (`%LOCALAPPDATA%\Programs\Homie`), allowing non-admin installation without UAC prompt.
   - Automatically supports machine-wide installation to `C:\Program Files\Homie` if elevated (`/ALLUSERS`).
3. **Shortcuts & Icons**:
   - Start Menu: `{autoprograms}\Homie`
   - Desktop Shortcut: `{autodesktop}\Homie` (optional task)
   - Startup Tray: `{autostartup}\Homie --tray` (optional task to run minimized in system tray on login)
4. **URL Protocol Handler**:
   - Registers `homie://` protocol in Windows registry (`HKA\Software\Classes\homie`).
   - Allows external applications or browsers to trigger Homie actions (e.g. `homie://chat?prompt=hello`, `homie://omnibar`).
5. **Windows Run / CMD Integration**:
   - Registers Windows App Paths (`HKA\Software\Microsoft\Windows\CurrentVersion\App Paths\Homie.exe`).
   - Typing `homie` in the Windows Run dialog (<kbd>Win</kbd> + <kbd>R</kbd>) or Command Prompt instantly launches Homie.
6. **Silent & Unattended Enterprise Deployment**:
   ```cmd
   Homie-Setup-1.0.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
   ```
7. **Clean Uninstallation**:
   - Fully removes application files, staging directories (`.homie_staging`), and registry keys.

---

## 4. GitHub Actions CI/CD Release Pipeline

To automate the compilation and publishing of Homie releases on every Git tag (`v*.*.*`), create `.github/workflows/release.yml`:

```yaml
name: Release Engineering Pipeline

on:
  push:
    tags:
      - "v*.*.*"
  workflow_dispatch:
    inputs:
      version:
        description: "Release version (e.g. 1.0.0)"
        required: true
        default: "1.0.0"

jobs:
  build-windows:
    name: Build Windows Distribution
    runs-on: windows-latest
    permissions:
      contents: write

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pyinstaller>=6.0.0

      - name: Install Inno Setup 6
        run: |
          choco install innosetup --no-progress
          echo "C:\Program Files (x86)\Inno Setup 6" >> $env:GITHUB_PATH

      - name: Extract Version
        id: get_version
        shell: pwsh
        run: |
          $ver = "${{ github.event.inputs.version }}"
          if (-not $ver) {
            $ver = "${{ github.ref_name }}".TrimStart("v")
          }
          echo "VERSION=$ver" >> $env:GITHUB_OUTPUT

      - name: Build Standalone Executable (PyInstaller)
        run: |
          python scripts/build_standalone.py --clean --version ${{ steps.get_version.outputs.VERSION }}

      - name: Compile Inno Setup Installer
        run: |
          iscc /DMyAppVersion=${{ steps.get_version.outputs.VERSION }} /Q scripts/homie_installer.iss

      - name: Build Portable Zip Bundle
        run: |
          python scripts/package_homie.py --portable --version ${{ steps.get_version.outputs.VERSION }}

      - name: Sign Binaries (Authenticode)
        if: env.SIGNING_CERT_BASE64 != ''
        env:
          SIGNING_CERT_BASE64: ${{ secrets.WINDOWS_CERT_BASE64 }}
          CERT_PASSWORD: ${{ secrets.WINDOWS_CERT_PASSWORD }}
        shell: pwsh
        run: |
          $certBytes = [Convert]::FromBase64String($env:SIGNING_CERT_BASE64)
          [IO.File]::WriteAllBytes("cert.pfx", $certBytes)
          & "signtool.exe" sign /f cert.pfx /p $env:CERT_PASSWORD /fd sha256 /tr http://timestamp.digicert.com /td sha256 dist\Homie\Homie.exe
          & "signtool.exe" sign /f cert.pfx /p $env:CERT_PASSWORD /fd sha256 /tr http://timestamp.digicert.com /td sha256 dist\Homie-Setup-${{ steps.get_version.outputs.VERSION }}.exe
          Remove-Item cert.pfx -Force

      - name: Generate SHA-256 Checksums
        shell: pwsh
        run: |
          Get-ChildItem -Path dist -Filter "*.exe", "*.zip" | ForEach-Object {
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            "$hash  $($_.Name)" | Out-File -Append -FilePath "dist/SHA256SUMS.txt" -Encoding ascii
          }

      - name: Publish GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/Homie-Setup-*.exe
            dist/Homie-Windows-x64-portable-*.zip
            dist/SHA256SUMS.txt
          generate_release_notes: true
```

---

## 5. Windows Package Manager (Winget) Manifest Specification

To publish Homie to the official Microsoft `winget-pkgs` repository:

### 5.1 Package Directory Layout
```text
manifests/
└── h/
    └── HomieAI/
        └── Homie/
            └── 1.0.0/
                ├── HomieAI.Homie.yaml
                ├── HomieAI.Homie.installer.yaml
                └── HomieAI.Homie.locale.en-US.yaml
```

### 5.2 Version Manifest: `HomieAI.Homie.yaml`
```yaml
PackageIdentifier: HomieAI.Homie
PackageVersion: 1.0.0
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
```

### 5.3 Installer Manifest: `HomieAI.Homie.installer.yaml`
```yaml
PackageIdentifier: HomieAI.Homie
PackageVersion: 1.0.0
InstallerType: inno
Scope: user
InstallModes:
  - interactive
  - silent
  - silentWithProgress
InstallerSwitches:
  Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  SilentWithProgress: /SILENT /SUPPRESSMSGBOXES /NORESTART
UpgradeBehavior: install
Protocols:
  - homie
Commands:
  - homie
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/homie-ai/homie/releases/download/v1.0.0/Homie-Setup-1.0.0.exe
    InstallerSha256: <CALCULATED_SHA256_OF_HOMIE_SETUP_EXE>
ManifestType: installer
ManifestVersion: 1.6.0
```

### 5.4 Locale Manifest: `HomieAI.Homie.locale.en-US.yaml`
```yaml
PackageIdentifier: HomieAI.Homie
PackageVersion: 1.0.0
PackageLocale: en-US
Publisher: Homie AI
PublisherUrl: https://github.com/homie-ai/homie
PublisherSupportUrl: https://github.com/homie-ai/homie/issues
PrivacyUrl: https://github.com/homie-ai/homie/blob/master/SECURITY_NOTES.md
PackageName: Homie
PackageUrl: https://github.com/homie-ai/homie
License: MIT
LicenseUrl: https://github.com/homie-ai/homie/blob/master/LICENSE
Copyright: Copyright (c) 2026 Homie AI
ShortDescription: Offline-first voice assistant, Raycast-style omnibar, and autonomous desktop automation companion.
Description: |
  Homie is a next-generation Windows desktop AI assistant.
  Features include:
  - Floating Raycast-style Omnibar (<kbd>Ctrl</kbd> + <kbd>Space</kbd>).
  - Sub-400ms Streaming Voice Pipeline with local Whisper and OneCore neural TTS.
  - Interactive Canvas for visual document editing, tables, and live widgets.
  - Multi-tier security governance with step-up verification and audit logging.
  - Offline-first operation with optional Claude AI cloud synthesis.
Tags:
  - ai
  - assistant
  - voice
  - omnibar
  - productivity
  - automation
ManifestType: defaultLocale
ManifestVersion: 1.6.0
```

### 5.5 Submitting to Winget
Using the official `wingetcreate` CLI tool:
```powershell
# Install wingetcreate
winget install Microsoft.WingetCreate

# Generate and submit manifests automatically
wingetcreate new https://github.com/homie-ai/homie/releases/download/v1.0.0/Homie-Setup-1.0.0.exe
```

---

## 6. Code Signing & Security Verification

### 6.1 Windows Authenticode Signing
To eliminate Windows SmartScreen warnings ("Windows protected your PC"), sign both the executable and setup installer:
```powershell
signtool.exe sign `
  /tr http://timestamp.digicert.com `
  /td sha256 `
  /fd sha256 `
  /a `
  dist\Homie\Homie.exe

signtool.exe sign `
  /tr http://timestamp.digicert.com `
  /td sha256 `
  /fd sha256 `
  /a `
  dist\Homie-Setup-1.0.0.exe
```

### 6.2 Ed25519 Auto-Update Manifest Signing
For in-app auto-updates (`update_verifier.py`), manifests must be signed offline with the publisher's private Ed25519 key:
```powershell
# Generate signed update manifest for deployment
python scripts/sign_release.py
```
`update_verifier.py` enforces:
1. Strict SHA-256 payload equality.
2. Canonical JSON encoding.
3. Monotonic `version_epoch` rollback prevention.
4. Expiration timestamp (`expires_at`) validation.

---

## 7. Verification Checklist for Releases

- [ ] All UI templates (`ui/chat.html`, `ui/omnibar.html`, `ui/canvas.html`) render properly in bundled Webview2.
- [ ] Application icon (`ui/AppIcon.ico`) displays correctly in taskbar, system tray, and Start Menu.
- [ ] Silent installer (`Homie-Setup-1.0.0.exe /VERYSILENT`) completes with exit code 0.
- [ ] Custom URI scheme `homie://` activates the application.
- [ ] Uninstaller removes binary and cleans registry entries without leaving zombie processes.
