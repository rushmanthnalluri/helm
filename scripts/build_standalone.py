"""Build the Windows onedir distribution from a clean source checkout."""

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "helm.spec"
OUTPUT_DIR = ROOT / "dist" / "Helm"
CHECKSUMS_FILE = ROOT / "dist" / "Helm.sha256"


def write_checksums() -> None:
    entries = []
    for path in sorted(OUTPUT_DIR.rglob("*")):
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(OUTPUT_DIR).as_posix()}")
    CHECKSUMS_FILE.write_text("\n".join(entries) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="remove PyInstaller caches before building")
    args = parser.parse_args()

    if not SPEC.is_file():
        parser.error(f"PyInstaller spec is missing: {SPEC}")

    if args.clean:
        expected_output = (ROOT / "dist" / "Helm").resolve()
        expected_parent = (ROOT / "dist").resolve()
        if expected_output.parent != expected_parent or expected_output.name != "Helm":
            parser.error("Refusing to clean an unexpected output path.")
        if expected_output.exists():
            shutil.rmtree(expected_output)
        if CHECKSUMS_FILE.exists():
            CHECKSUMS_FILE.unlink()

    command = [sys.executable, "-m", "PyInstaller", str(SPEC), "--noconfirm"]
    if args.clean:
        command.append("--clean")

    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        return result.returncode

    executable = OUTPUT_DIR / "Helm.exe"
    if not executable.is_file():
        print(f"Build finished without the expected executable: {executable}", file=sys.stderr)
        return 1

    write_checksums()
    print(f"Built {executable}")
    print(f"Wrote {CHECKSUMS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
