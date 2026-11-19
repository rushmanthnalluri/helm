# Helm Distribution & Release Engineering Guide

This guide documents the release engineering, packaging, and distribution architecture for the **Helm Windows Desktop Assistant**.

---

## 1. Distribution Channels Overview

Helm provides three modern distribution channels for Windows 10/11 x64 systems:

| Distribution Channel | Target Artifact | Target Audience & Use Case |
|---|---|---|
| **Modern MSIX Package** | `packaging/Helm.msix` | Official Windows store-compatible signed package. Installs natively with zero elevation prompts, isolated execution, seamless Windows Start integration, and clean uninstallation. |
| **WinGet Package Manager** | `winget install HelmAI.Helm` | Command-line deployment via Windows Package Manager. Manifest verified with authentic SHA-256 digest in `packaging/winget/Helm.yaml`. |
| **Velopack Monotonic Updates** | `helm_update_manifest.json` | Incremental cryptographic delta updates verified by pinned Ed25519 digital signatures (`helm/core/update_verifier.py`) with monotonic anti-rollback epoch protection. |

---

## 2. Packaging Toolchain & Scripts

Automated release scripts are located under [`scripts/`](file:///d:/homie/scripts):

### 2.1 Single-Click MSIX Packager: `scripts/build_msix.ps1`

Compiles the Windows modern package bundle using `MakeAppx.exe` and `SignTool.exe` based on [`packaging/AppxManifest.xml`](file:///d:/homie/packaging/AppxManifest.xml):

```powershell
# Build signed MSIX package
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -Version "1.0.0"
```

The MSIX package declares:
- **Application ID**: `HelmAI.Helm`
- **Capabilities**: RunFullTrust, BackgroundTasks
- **Visual Assets**: Windows 11 high-DPI icons (`Square44x44Logo.png`, `Square150x150Logo.png`, `SplashScreen.png`)

### 2.2 WinGet Manifest: `packaging/winget/Helm.yaml`

Official singleton manifest for Windows Package Manager:
```yaml
PackageIdentifier: HelmAI.Helm
PackageVersion: 1.0.0
PackageName: Helm
Publisher: Helm AI
License: MIT
ShortDescription: Sovereign Windows Desktop AI Assistant
Installers:
  - Architecture: x64
    InstallerType: msix
    InstallerUrl: https://github.com/helm-ai/helm/releases/download/v1.0.0/Helm.msix
    InstallerSha256: 1064D9341F556732739DFE104743DF8CC9BE517A236F663A7C70518835265577
    SignatureSha256: 1064D9341F556732739DFE104743DF8CC9BE517A236F663A7C70518835265577
ManifestType: singleton
ManifestVersion: 1.6.0
```

Install locally via WinGet:
```powershell
winget install --manifest packaging/winget/Helm.yaml
```

### 2.3 Velopack Setup & Delta Releases: `scripts/setup_velopack.py`

Manages Velopack update deployment and packaging.

---

## 3. Cryptographic Verification & Offline Signing

### 3.1 Ed25519 Manifest Signing: `scripts/sign_release.py`

For in-app auto-updates, manifests are signed offline using the publisher's private Ed25519 key:

```powershell
python scripts/sign_release.py
```

`helm.core.update_verifier` enforces:
1. Pinned publisher public key hash assertion (`PINNED_PUBLISHER_KEY_SHA256`).
2. Canonical JSON encoding.
3. Strict SHA-256 digest validation of all payload files.
4. Monotonic `version_epoch` rollback protection.

---

## 4. Pre-Release Verification Checklist

- [ ] All 10 suites in the regression battery pass 100%:
  ```powershell
  python -m pytest tests/test_performance_benchmarks.py tests/test_deterministic_uia.py tests/test_caret_dictation.py tests/test_msix_packaging.py tests/test_zero_config_fallback.py tests/test_telemetry.py tests/test_sync_engine.py tests/test_live_voice.py tests/test_plugin_ecosystem.py tests/test_os_hal.py -q
  ```
- [ ] Active UI templates (`ui/chat.html`, `ui/canvas.html`, `ui/omnibar.html`) load cleanly without JavaScript errors.
- [ ] Application icons (`ui/AppIcon.ico`, `ui/AppIcon.png`) display correctly in taskbar and system tray.
- [ ] Installer SHA-256 matches the WinGet manifest.
