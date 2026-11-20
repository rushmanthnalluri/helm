# Helm distribution status

The repository contains a clean-checkout Windows build path with a pinned, hash-checked Python dependency lock, but it does not contain a published release artifact. The MSIX and WinGet package identity is `Helm.DesktopAI`. Source setup and release commands are documented in [PACKAGING.md](PACKAGING.md).

## Build outputs

- `python scripts/build_standalone.py --clean` creates `dist/Helm/Helm.exe`, the onedir runtime files, and `dist/Helm.sha256`.
- `scripts/build_msix.ps1` creates `dist/Helm.msix`. A distributable release requires a publisher certificate matching the package Publisher and a verified signature.
- `scripts/generate_winget_manifest.py` creates a release-specific WinGet manifest from the signed MSIX's SHA-256 and published HTTPS URL.

The checked-in `packaging/winget/Helm.yaml` is a template only. Its placeholder URL and checksum are not valid release values. The signed release workflow generates a completed manifest after building and signing the artifact.

## Publishing

Push a `vMAJOR.MINOR.PATCH` tag after configuring the signing certificate secrets listed in [PACKAGING.md](PACKAGING.md). The release workflow builds from a clean checkout, verifies the MSIX signature, calculates checksums, generates the WinGet manifest, and attaches the files to the GitHub release. Submit the generated manifest to the community WinGet repository separately.

The code also contains an Ed25519 update-verification component. This repository does not currently publish a signed update feed, so this document makes no claim that automatic updates are available to users.
