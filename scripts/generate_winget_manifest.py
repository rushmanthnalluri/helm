"""Create a release-specific WinGet manifest from a signed MSIX artifact."""

import argparse
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "packaging" / "winget" / "Helm.yaml"


def replace_one(text: str, field: str, value: str) -> str:
    pattern = rf"^{re.escape(field)}:.*$"
    updated, count = re.subn(pattern, f"{field}: {value}", text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"The WinGet template must contain one {field} field.")
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path, help="signed Helm.msix file")
    parser.add_argument("--version", required=True, help="release version, such as 1.2.3")
    parser.add_argument("--url", required=True, help="HTTPS URL for the published signed MSIX")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "Helm.yaml")
    args = parser.parse_args()

    artifact = args.artifact.resolve()
    if not artifact.is_file():
        parser.error(f"MSIX artifact does not exist: {artifact}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        parser.error("Version must use three numeric components, for example 1.2.3.")
    if not args.url.startswith("https://") or "example.invalid" in args.url:
        parser.error("Installer URL must be a published HTTPS URL.")

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest().upper()
    text = TEMPLATE.read_text(encoding="utf-8")
    if "PackageIdentifier: Helm.DesktopAI" not in text:
        parser.error("Unexpected package identifier in WinGet template.")

    text = replace_one(text, "PackageVersion", args.version)
    text = replace_one(text, "InstallerUrl", args.url)
    text = replace_one(text, "InstallerSha256", digest)
    text = text.replace("# Release template only. Generate release values from a signed MSIX with\n# scripts/generate_winget_manifest.py before submitting this manifest.\n", "")

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote release manifest {output} with SHA-256 {digest}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
