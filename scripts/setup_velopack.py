#!/usr/bin/env python3
"""scripts/setup_velopack.py - Velopack Toolchain Setup & Packaging Automation.

Automates the packaging and release pipeline for Helm using Velopack:
1. Displays installation instructions and verifies local presence of the `vpk` CLI.
2. Packages compiled PyInstaller binaries into a delta-update capable Velopack release:
   vpk pack --packId Helm --packVersion 1.0.0 --packDir dist\\helm --mainExe helm.exe
3. Generates release assets in `releases/` ready for cloud/CDN distribution.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = BASE_DIR / "dist"
RELEASES_DIR = BASE_DIR / "releases"

VPK_INSTALL_GUIDE = """
======================================================================
 Velopack CLI (`vpk`) Installation Guide
======================================================================

Velopack requires the `vpk` cross-platform packaging CLI.
Choose one of the installation methods below:

1. VIA .NET TOOL (Recommended if .NET 8+ SDK / Runtime is present):
   > dotnet tool install -g vpk
   Update anytime with:
   > dotnet tool update -g vpk

2. VIA WINGET (Windows Package Manager):
   > winget install velopack

3. VIA CARGO / RUST:
   > cargo install vpk

4. STANDALONE GITHUB RELEASE:
   Download the latest prebuilt `vpk-windows-x64.zip` from:
   https://github.com/velopack/velopack/releases/latest
   Extract `vpk.exe` and place it in your system PATH or %USERPROFILE%\\.dotnet\\tools.

5. PYTHON SDK INSTALLATION:
   > pip install velopack
======================================================================
"""


def log_info(msg: str) -> None:
    print(f"\033[94m[*] {msg}\033[0m")


def log_success(msg: str) -> None:
    print(f"\033[92m[+] {msg}\033[0m")


def log_warn(msg: str) -> None:
    print(f"\033[93m[!] {msg}\033[0m")


def log_error(msg: str) -> None:
    print(f"\033[91m[-] {msg}\033[0m")


def find_vpk_binary() -> Optional[Path]:
    """Locates the vpk executable on PATH or in default .NET tool directories."""
    # 1. Standard PATH
    exe_name = "vpk.exe" if sys.platform == "win32" else "vpk"
    path_found = shutil.which(exe_name)
    if path_found:
        return Path(path_found)

    # 2. User profile dotnet tools
    user_profile = Path(os.environ.get("USERPROFILE", "~")).expanduser()
    candidate = user_profile / ".dotnet" / "tools" / exe_name
    if candidate.exists() and os.access(candidate, os.X_OK):
        return candidate

    return None


def show_install_instructions() -> None:
    """Prints clear instructions on installing vpk and velopack."""
    print(VPK_INSTALL_GUIDE)


def resolve_pack_dir(user_path: Optional[str]) -> Path:
    """Finds the directory containing compiled Helm binaries."""
    if user_path:
        p = Path(user_path).resolve()
        if p.is_dir():
            return p

    # Standard locations
    for candidate in [DIST_DIR / "helm", DIST_DIR / "Helm"]:
        if candidate.is_dir():
            return candidate

    return DIST_DIR / "helm"


def resolve_main_exe(pack_dir: Path, user_exe: Optional[str]) -> str:
    """Detects main executable name inside packaging directory."""
    if user_exe and (pack_dir / user_exe).exists():
        return user_exe

    for name in ["helm.exe", "Helm.exe"]:
        if (pack_dir / name).exists():
            return name

    return "helm.exe"


def run_velopack_packaging(
    pack_id: str,
    pack_version: str,
    pack_dir: Path,
    main_exe: str,
    output_dir: Path,
    icon_path: Optional[Path] = None,
    dry_run: bool = False,
) -> bool:
    """Executes the vpk pack command to generate release artifacts."""
    vpk_bin = find_vpk_binary()
    
    cmd = [
        str(vpk_bin) if vpk_bin else "vpk",
        "pack",
        "--packId", pack_id,
        "--packVersion", pack_version,
        "--packDir", str(pack_dir),
        "--mainExe", main_exe,
        "--outputDir", str(output_dir),
    ]

    if icon_path and icon_path.exists():
        cmd.extend(["--icon", str(icon_path)])

    log_info(f"Target Packaging Command: {' '.join(cmd)}")

    if dry_run:
        log_success("Dry run requested. Command verified without execution.")
        return True

    if not vpk_bin:
        log_error("Velopack CLI (`vpk`) executable was not found.")
        show_install_instructions()
        return False

    output_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Running Velopack packager (packId={pack_id}, version={pack_version})...")

    try:
        proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
        print(proc.stdout)
        log_success(f"Velopack release generated successfully in: {output_dir}")
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Velopack execution failed with code {e.returncode}:")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Helm Velopack Auto-Update Packager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--packId",
        default="Helm",
        help="Unique package ID for Velopack (default: Helm)",
    )
    parser.add_argument(
        "--packVersion",
        default="1.0.0",
        help="Semantic release version (e.g., 1.0.0)",
    )
    parser.add_argument(
        "--packDir",
        default=None,
        help="Directory containing PyInstaller output (default: dist/helm or dist/Helm)",
    )
    parser.add_argument(
        "--mainExe",
        default=None,
        help="Name of main executable (default: helm.exe or Helm.exe)",
    )
    parser.add_argument(
        "--outputDir",
        default=str(RELEASES_DIR),
        help="Destination directory for update packages (default: releases)",
    )
    parser.add_argument(
        "--icon",
        default=str(BASE_DIR / "ui" / "AppIcon.ico"),
        help="Application icon file",
    )
    parser.add_argument(
        "--install-help",
        action="store_true",
        help="Print vpk CLI installation instructions and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate parameters and display pack command without executing",
    )

    args = parser.parse_args()

    if args.install_help:
        show_install_instructions()
        return 0

    print("=" * 65)
    print(" Helm Velopack Auto-Update Packager")
    print("=" * 65)

    vpk_bin = find_vpk_binary()
    if vpk_bin:
        log_success(f"Found vpk CLI at: {vpk_bin}")
    else:
        log_warn("vpk CLI not found in PATH or standard user directories.")
        if not args.dry_run:
            show_install_instructions()

    pack_dir = resolve_pack_dir(args.packDir)
    main_exe = resolve_main_exe(pack_dir, args.mainExe)
    output_dir = Path(args.outputDir).resolve()
    icon_path = Path(args.icon).resolve() if args.icon else None

    log_info(f"Source binaries directory: {pack_dir}")
    log_info(f"Target main executable:    {main_exe}")
    log_info(f"Target output directory:   {output_dir}")

    success = run_velopack_packaging(
        pack_id=args.packId,
        pack_version=args.packVersion,
        pack_dir=pack_dir,
        main_exe=main_exe,
        output_dir=output_dir,
        icon_path=icon_path,
        dry_run=args.dry_run,
    )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
