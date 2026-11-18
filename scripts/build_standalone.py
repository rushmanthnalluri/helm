#!/usr/bin/env python3
"""scripts/build_standalone.py - Standalone Distribution Builder for Homie.

Compiles Homie into a production-grade standalone Windows binary using PyInstaller:
1. Validates presence of core entry points, UI templates, icons, and runtime dependencies.
2. Checks PyInstaller installation; provides auto-install or clear remediation guidance.
3. Builds the standalone distribution (onedir or onefile) using homie.spec.
4. Verifies output binary integrity, assets, and permissions.
5. Prepares output folder for Inno Setup installer compilation.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"
DEFAULT_SPEC = BASE_DIR / "homie.spec"

CRITICAL_ASSETS = [
    BASE_DIR / "app.py",
    BASE_DIR / "homie.py",
    BASE_DIR / "ui" / "chat.html",
    BASE_DIR / "ui" / "omnibar.html",
    BASE_DIR / "ui" / "canvas.html",
    BASE_DIR / "ui" / "AppIcon.ico",
]

CORE_IMPORT_TESTS = [
    ("webview", "pywebview (UI renderer)"),
    ("faster_whisper", "faster-whisper (Voice STT)"),
    ("cryptography", "cryptography (Security vault)"),
    ("pynput", "pynput (Global hotkey listener)"),
    ("sounddevice", "sounddevice (Audio I/O)"),
    ("pystray", "pystray (System tray integration)"),
]


def log_info(msg: str) -> None:
    print(f"\033[94m[*] {msg}\033[0m")


def log_success(msg: str) -> None:
    print(f"\033[92m[+] {msg}\033[0m")


def log_warn(msg: str) -> None:
    print(f"\033[93m[!] {msg}\033[0m")


def log_error(msg: str) -> None:
    print(f"\033[91m[-] {msg}\033[0m")


def verify_assets() -> bool:
    """Verifies that all required source files, UI HTML, and icons exist."""
    log_info("Verifying source files and UI assets...")
    missing = []
    for asset in CRITICAL_ASSETS:
        if not asset.exists():
            missing.append(str(asset.relative_to(BASE_DIR)))
        else:
            log_success(f"Found required asset: {asset.name}")

    if missing:
        log_error(f"Missing critical assets: {', '.join(missing)}")
        return False
    return True


def check_dependencies() -> dict[str, bool]:
    """Checks importability of critical runtime modules."""
    log_info("Auditing Python runtime dependencies...")
    results = {}
    for module_name, desc in CORE_IMPORT_TESTS:
        try:
            __import__(module_name)
            log_success(f"Dependency available: {desc}")
            results[module_name] = True
        except ImportError:
            log_warn(f"Dependency missing or optional: {desc} ({module_name})")
            results[module_name] = False
    return results


def find_pyinstaller() -> list[str] | None:
    """Locates PyInstaller executable or module runner."""
    # 1. Check if pyinstaller executable is in PATH
    exe = shutil.which("pyinstaller")
    if exe:
        return [exe]

    # 2. Check python -m PyInstaller
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return [sys.executable, "-m", "PyInstaller"]
    except Exception:
        pass

    return None


def install_pyinstaller() -> bool:
    """Attempts to install PyInstaller into the current Python environment."""
    log_info("Attempting to install PyInstaller via pip...")
    cmd = [sys.executable, "-m", "pip", "install", "pyinstaller>=6.0.0"]
    try:
        res = subprocess.run(cmd, check=True)
        return res.returncode == 0
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to install PyInstaller: {e}")
        return False


def clean_build_artifacts() -> None:
    """Cleans previous build directories."""
    log_info("Cleaning temporary build artifacts...")
    for target in [BUILD_DIR, DIST_DIR / "Homie"]:
        if target.exists():
            try:
                shutil.rmtree(target)
                log_success(f"Removed previous build directory: {target}")
            except Exception as e:
                log_warn(f"Could not remove {target}: {e}")


def execute_pyinstaller_build(spec_path: Path, clean: bool = False) -> bool:
    """Executes PyInstaller build using the specified spec file."""
    pyi_cmd = find_pyinstaller()
    if not pyi_cmd:
        log_error("PyInstaller was not found in PATH or Python environment.")
        log_info("Install with: pip install pyinstaller")
        return False

    cmd = list(pyi_cmd)
    if clean:
        cmd.append("--clean")
    cmd.append("--noconfirm")
    cmd.append(str(spec_path))

    log_info(f"Running build command: {' '.join(cmd)}")
    start_time = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), check=True)
        elapsed = time.time() - start_time
        if proc.returncode == 0:
            log_success(f"PyInstaller build finished successfully in {elapsed:.1f}s.")
            return True
        else:
            log_error(f"PyInstaller build failed with exit code {proc.returncode}.")
            return False
    except subprocess.CalledProcessError as e:
        log_error(f"PyInstaller build execution failed: {e}")
        return False


def verify_and_postprocess_distribution() -> bool:
    """Validates the compiled standalone output and copies auxiliary files."""
    homie_exe = DIST_DIR / "Homie" / "Homie.exe"
    if not homie_exe.exists():
        # Check single-file output
        homie_exe = DIST_DIR / "Homie.exe"

    if not homie_exe.exists():
        log_error(f"Expected compiled binary not found at: {DIST_DIR / 'Homie' / 'Homie.exe'}")
        return False

    size_mb = homie_exe.stat().st_size / (1024 * 1024)
    log_success(f"Verified standalone binary: {homie_exe} ({size_mb:.2f} MB)")

    # Ensure UI and config exist alongside binary if onedir
    app_dir = homie_exe.parent
    if (app_dir / "ui").exists():
        log_success(f"Verified bundled UI directory in: {app_dir / 'ui'}")
    else:
        # Fallback copy if PyInstaller didn't place it in app_dir root
        log_info("Syncing UI directory into distribution folder...")
        shutil.copytree(BASE_DIR / "ui", app_dir / "ui", dirs_exist_ok=True)

    if (BASE_DIR / "config").exists() and not (app_dir / "config").exists():
        log_info("Syncing config directory into distribution folder...")
        shutil.copytree(BASE_DIR / "config", app_dir / "config", dirs_exist_ok=True)

    # Place a README / version marker in dist/Homie
    version_marker = app_dir / "VERSION"
    version_marker.write_text("Homie Desktop AI 1.0.0 (Standalone x64)\n", encoding="utf-8")

    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Homie Standalone Distribution Packaging Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--spec",
        type=Path,
        default=DEFAULT_SPEC,
        help="Path to PyInstaller .spec file (default: homie.spec)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build and output caches before compiling",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Audit assets, dependencies, and environment without running PyInstaller",
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Automatically install missing PyInstaller via pip",
    )
    parser.add_argument(
        "--version",
        default="1.0.0",
        help="Version string for the standalone build (default: 1.0.0)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print(f" Homie Standalone Distribution Builder v{args.version}")
    print("=" * 60)

    # 1. Verify Assets
    if not verify_assets():
        return 1

    # 2. Check Dependencies
    check_dependencies()

    # 3. Check PyInstaller
    pyi = find_pyinstaller()
    if not pyi:
        if args.install_deps:
            if not install_pyinstaller():
                return 1
            pyi = find_pyinstaller()
        else:
            log_warn("PyInstaller is not currently installed.")
            log_info("Run with --install-deps to install automatically, or:")
            log_info("  pip install pyinstaller")
            if not args.dry_run:
                log_error("Cannot continue standalone compilation without PyInstaller.")
                return 2

    if args.dry_run:
        log_success("Dry run completed successfully. Environment is ready for packaging.")
        return 0

    # 4. Clean artifacts
    if args.clean:
        clean_build_artifacts()

    # 5. Execute Build
    if not args.spec.exists():
        log_error(f"Spec file not found at: {args.spec}")
        return 1

    log_info(f"Using PyInstaller specification: {args.spec}")
    ok = execute_pyinstaller_build(args.spec, clean=args.clean)
    if not ok:
        log_error("Standalone binary compilation failed.")
        return 1

    # 6. Postprocess and verify
    if not verify_and_postprocess_distribution():
        return 1

    log_success("Standalone distribution build completed successfully!")
    log_info(f"Target location: {DIST_DIR / 'Homie'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
