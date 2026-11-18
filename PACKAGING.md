# Homie Packaging & Distribution Pipeline

Homie provides a modern, production-grade release toolchain for Windows:
1. **PyInstaller**: Compiles Python source, native libraries (WinRT, CTranslate2, PortAudio), and UI assets into a standalone directory (`dist/homie`).
2. **MSIX**: Windows App package with isolated registry virtualization, identity enforcement, visual tiles, file-type associations (`.homie`, `.hnote`), and enterprise deployment.
3. **Velopack**: High-performance, delta-compressed auto-updater (successor to Squirrel) with atomic background updates and restart coordination.
4. **WinGet**: Windows Package Manager community manifest for single-command installation (`winget install Homie.DesktopAI`).

---

## Architecture Overview

```
                      ┌──────────────────────┐
                      │   Homie Source Code   │
                      │ (app.py, UI, engines)│
                      └──────────┬───────────┘
                                 │
                                 ▼
                     [ PyInstaller Compiler ]
                        (homie.spec --clean)
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    dist/homie/ (onedir)  │
                    │   Homie.exe + DLLs + UI  │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
  [ MSIX Packaging Pipeline ]             [ Velopack Update Pipeline ]
   scripts/build_msix.ps1                  scripts/setup_velopack.py
   - packaging/AppxManifest.xml            - vpk pack --packId Homie
   - packaging/assets (Pillow PNGs)        - Releases/ (full + delta nupkg)
   - makeappx.exe pack                     - homie_updater.py client
   - signtool.exe sign                               │
             │                                       │
             ▼                                       ▼
     dist/Homie.msix                           Delta Release CDN
             │
             ▼
  [ WinGet Distribution ]
   packaging/winget/Homie.yaml
   winget install Homie.DesktopAI
```

---

## 1. Prerequisites & Toolchain Setup

### Python Dependencies
Ensure all packaging and runtime dependencies are installed:
```powershell
pip install -r requirements.txt
pip install pyinstaller>=6.0.0 pillow>=10.0.0
```

### Windows 10/11 SDK (for MSIX)
`makeappx.exe` and `signtool.exe` are bundled with the Windows SDK:
- Download via [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) or through the **Visual Studio Installer** under "Desktop development with C++" -> "Windows 10/11 SDK".
- Default installation locations searched automatically by `build_msix.ps1`:
  - `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\`
  - `C:\Program Files\Windows Kits\10\bin\<version>\x64\`

### Velopack CLI (`vpk`)
Install the cross-platform packaging CLI:
```powershell
# Option A: .NET Global Tool (Recommended)
dotnet tool install -g vpk
dotnet tool update -g vpk

# Option B: WinGet
winget install velopack

# Option C: Python SDK
pip install velopack
```

---

## 2. Compiling the Standalone Binary (PyInstaller)

The standalone binary is generated using `homie.spec`, which bundles pywebview, faster-whisper, winrt, cryptography, sounddevice, and on-disk assets:
```powershell
# Manual PyInstaller compilation
pyinstaller homie.spec --clean --noconfirm

# Or using the build script
python scripts/build_standalone.py --clean
```
The output is staged at `dist/homie/` (with `Homie.exe` and `ui/`).

---

## 3. MSIX Packaging Pipeline

The script `scripts/build_msix.ps1` automates the entire MSIX packaging process:
1. Validates and generates required visual assets (`packaging/assets/*.png`) via Pillow:
   - `Square44x44Logo.png` (Taskbar / App list icon)
   - `Square150x150Logo.png` (Start menu medium tile)
   - `Square310x310Logo.png` (Start menu large tile)
   - `Wide310x150Logo.png` (Start menu wide tile)
   - `StoreLogo.png` (Store & installer icon)
   - `SplashScreen.png` (App launch splash)
2. Writes a valid `packaging/AppxManifest.xml` declaring:
   - Package identity: `Name="Homie.DesktopAI"`, `Publisher="CN=Homie, ..."`, `Version="1.0.0.0"`
   - Capability: `runFullTrust` (restricted capability for desktop apps)
   - File type associations: `.homie` and `.hnote`
3. Stages the manifest and assets into `dist/homie/`.
4. Executes `makeappx.exe pack /d dist\homie /p dist\Homie.msix /o`.
5. Signs the package with `signtool.exe`.

### Running the MSIX Build
```powershell
# Standard build (recompiles EXE, packages MSIX, signs if cert present)
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -Version "1.0.0.0"

# Packaging without recompiling EXE (fast repack)
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -SkipBuildExe

# Dry-run validation (checks manifest, assets, and tools without compiling)
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -DryRun
```

---

## 4. Code Signing & Local Sideloading

MSIX packages **must be cryptographically signed** to install on Windows.

### Creating a Self-Signed Developer Certificate
Run PowerShell as Administrator:
```powershell
# 1. Create code signing certificate in CurrentUser\My
$cert = New-SelfSignedCertificate -Type Custom `
    -Subject "CN=Homie, O=Homie, L=San Francisco, S=CA, C=US" `
    -KeyUsage DigitalSignature `
    -FriendlyName "Homie Dev Cert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

# 2. Export PFX with password
$pwd = ConvertTo-SecureString -String "HomieSecret123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "packaging\HomieDev.pfx" -Password $pwd

# 3. Export public CER certificate for client installation
Export-Certificate -Cert $cert -FilePath "packaging\HomieDev.cer"

# 4. Trust certificate on local machine (Administrator prompt required)
Import-Certificate -FilePath "packaging\HomieDev.cer" -CertStoreLocation "Cert:\LocalMachine\TrustedPeople"
```

### Signing the MSIX Package
```powershell
# Sign with the exported PFX certificate:
signtool sign /fd SHA256 /f "packaging\HomieDev.pfx" /p "HomieSecret123!" /tr http://timestamp.digicert.com /td SHA256 dist\Homie.msix

# Or pass parameters directly to build_msix.ps1:
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 `
    -CertPath "packaging\HomieDev.pfx" `
    -CertPassword "HomieSecret123!"
```

---

## 5. Velopack Auto-Update Integration

Velopack manages frictionless background updates without administrative prompts.

### Packaging a Velopack Release
```powershell
# Using the setup_velopack automation script:
python scripts/setup_velopack.py --packVersion 1.0.0 --packDir dist/homie

# Or directly via vpk CLI:
vpk pack --packId Homie --packVersion 1.0.0 --packDir dist\homie --mainExe homie.exe --outputDir releases
```

### Generated Release Artifacts
Inside `releases/`:
- `Homie-1.0.0-full.nupkg`: Complete application package.
- `Homie-1.0.1-delta.nupkg`: Byte-level diff containing only changed binaries.
- `releases.win.json`: Release index ingested by client updaters.
- `Setup.exe`: Single-file web/offline bootstrapper.

### In-App Update Verification (`homie_updater.py`)
In Homie runtime code:
```python
from homie_updater import check_for_update, apply_update

# Check for new version against update server
update_info = check_for_update("https://releases.homie.internal/windows")
if update_info and update_info.get("is_available"):
    print(f"Update available: {update_info['target_version']}")
    # Download and apply update with restart
    apply_update(update_info, restart=True)
```

---

## 6. WinGet Manifest & Community Submission

Homie provides a singleton manifest for the official Windows Package Manager repository:
Path: `packaging/winget/Homie.yaml`

### Preparing a WinGet Release
1. Build and sign `dist/Homie.msix`.
2. Compute the SHA-256 checksum of the installer:
   ```powershell
   Get-FileHash dist\Homie.msix -Algorithm SHA256
   ```
3. Update `packaging/winget/Homie.yaml`:
   - Set `PackageVersion: <version>`
   - Set `InstallerUrl: https://github.com/homie-ai/homie/releases/download/v<version>/Homie.msix`
   - Paste the calculated `InstallerSha256` hash.

### Validating & Testing Locally
```powershell
# Validate manifest syntax against WinGet schema
winget validate --manifest packaging/winget/Homie.yaml

# Test local installation
winget install --manifest packaging/winget/Homie.yaml
```

### Submitting to microsoft/winget-pkgs
Submit using the official `wingetcreate` CLI:
```powershell
winget install Microsoft.WinGetCreate
wingetcreate submit packaging/winget/Homie.yaml
```
Alternatively, fork [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) and submit a pull request under `manifests/h/Homie/DesktopAI/<version>/`.

---

## 7. CI/CD Release Automation (GitHub Actions)

Example workflow (`.github/workflows/release.yml`):
```yaml
name: Build and Publish MSIX & Velopack Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Dependencies
        run: |
          pip install -r requirements.txt
          pip install pyinstaller pillow velopack

      - name: Install Velopack CLI
        run: dotnet tool install -g vpk

      - name: Build Standalone Binary
        run: pyinstaller homie.spec --clean --noconfirm

      - name: Build and Pack MSIX
        run: powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -SkipBuildExe -Version "${{ github.ref_name }}"

      - name: Create Velopack Release
        run: python scripts/setup_velopack.py --packVersion "${{ github.ref_name }}" --packDir dist/homie

      - name: Upload Release Artifacts
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/Homie.msix
            releases/*
```

---

## 8. Verification & QA Checklist

- [x] `packaging/AppxManifest.xml` contains all required MSIX attributes:
  - `Identity`: Name, Publisher, Version, ProcessorArchitecture
  - `Properties`: DisplayName, PublisherDisplayName, Logo, Description
  - `Capabilities`: `rescap:Capability Name="runFullTrust"`
  - `VisualElements`: Square150x150Logo, Square44x44Logo, DefaultTile, SplashScreen
  - `File associations`: `.homie`, `.hnote`
- [x] Placeholder PNG icons (44x44, 150x150, 310x310, StoreLogo, Wide310x150, SplashScreen) generated via Pillow in `packaging/assets/`.
- [x] `scripts/build_msix.ps1` supports `-DryRun`, `-SkipBuildExe`, `-SkipSign`, and custom versioning.
- [x] `scripts/setup_velopack.py` provides `vpk` installation guide, command generation, and release packaging.
- [x] `homie_updater.py` exposes `check_for_update()`, `apply_update()`, and `is_velopack_available()` with stub fallback.
- [x] `packaging/winget/Homie.yaml` conforms to WinGet singleton v1.6.0 schema (`PackageIdentifier`, `PackageVersion`, `InstallerUrl`, `InstallerType: msix`).
- [x] `requirements.txt` includes `velopack>=0.0.1` without version conflicts.
