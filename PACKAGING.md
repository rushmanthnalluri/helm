# Windows build and release

This checkout contains source and build workflows. It does not include a published MSIX or a ready-to-submit WinGet manifest. The package identity used by the MSIX and WinGet template is `Helm.DesktopAI`.

## Local setup

Use 64-bit Python 3.12 on Windows 10 or 11. Install the core desktop and local dictation dependencies:

```powershell
python -m pip install -r requirements.txt
```

Optional integrations and larger ML/TTS packages are listed in `requirements-optional.txt`:

```powershell
python -m pip install -r requirements-optional.txt
```

Local Whisper downloads its selected model on first use to `~/.config/helm/whisper`. Audio stays on-device for dictation and talk-to-Helm by default. Setting `speechCloudFallback` to `true` in `~/.config/helm/settings.json` allows the assistant voice path to send audio to Google's Speech Recognition service if local transcription fails.

## Standalone build

The checked-in PyInstaller entry point and spec produce an onedir build from a clean checkout. CI installs the checked-in Python 3.12 Windows x64 dependency lock with hashes. The runner image and Windows SDK still change over time, so byte-for-byte reproducibility is not claimed:

```powershell
python -m pip install -r requirements-build.txt
python scripts/build_standalone.py --clean
```

Outputs:

- `dist/Helm/Helm.exe` and its runtime files
- `dist/Helm.sha256`, with a SHA-256 checksum for each file in the onedir output

The build excludes the optional Torch, vector-search, provider-integration, and neural-TTS stacks. Install `requirements-optional.txt` in a source environment when you need those features.

## MSIX build

Install the Windows 10/11 SDK so `makeappx.exe` and `signtool.exe` are available. The signing certificate subject must match the Publisher value in `packaging/AppxManifest.xml`.

For a local unsigned package:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 -Version "1.0.0.0" -SkipSign
```

Unsigned packages are for local development only. To create a signed package, pass a publisher certificate and password:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_msix.ps1 `
  -Version "1.0.0.0" `
  -CertPath "C:\path\to\publisher.pfx" `
  -CertPassword $env:HELM_SIGNING_CERTIFICATE_PASSWORD
```

The script fails if MakeAppx or SignTool is missing, signing fails, or signature verification fails. It writes `dist/Helm.msix.sha256` only after packaging and signing complete. Verify it with:

```powershell
Get-FileHash dist/Helm.msix -Algorithm SHA256
Get-Content dist/Helm.msix.sha256
```

## Clean-checkout CI and releases

`.github/workflows/windows-build.yml` builds the standalone app from a fresh checkout on pull requests and pushes to `main` or `master`, then uploads the binary and checksums as a short-lived CI artifact. `requirements-build.lock.txt` pins and hashes the build dependencies for Python 3.12 on Windows x64. Regenerate it after changing build requirements with:

```powershell
uv pip compile requirements-build.txt --python-version 3.12 --python-platform x86_64-pc-windows-msvc --generate-hashes --output-file requirements-build.lock.txt
```

`.github/workflows/windows-release.yml` builds and publishes a signed MSIX when a `vMAJOR.MINOR.PATCH` tag is pushed. Configure these repository secrets first:

- `HELM_SIGNING_CERTIFICATE_BASE64`: base64-encoded publisher `.pfx`
- `HELM_SIGNING_CERTIFICATE_PASSWORD`: certificate password

The workflow verifies the signature, generates the release-specific WinGet manifest from the signed MSIX hash, and attaches the MSIX, checksums, and manifest to the GitHub release. A release tag without those secrets fails before publishing.

`packaging/winget/Helm.yaml` is a template with placeholder URL and checksum values. Do not submit it to WinGet. The release workflow generates `dist/Helm.yaml` with the actual release URL and SHA-256. A WinGet submission still requires a separate pull request to `microsoft/winget-pkgs`.
