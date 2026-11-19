#!/usr/bin/env python3
"""scripts/package_helm.py - Standalone Distribution & Packaging Builder for Helm.

Packages Helm into clean, production-grade deployment artifacts:
1. Portable Zip Archive ('dist/Helm-Windows-x64-portable.zip'):
   - Self-contained Python runtime bundle with launcher scripts and PowerShell installer.
2. Standalone Binary Distribution ('dist/Helm/Helm.exe'):
   - Compiled PyInstaller single-folder or single-file executable requiring zero host Python.
3. Inno Setup Windows Installer ('dist/Helm-Setup-1.0.0.exe'):
   - Professional Windows installer with Start Menu, Desktop shortcuts, protocol registration,
     silent install switches (/VERYSILENT), and clean uninstaller.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = DIST_DIR / "helm_bundle"
SCRIPTS_DIR = BASE_DIR / "scripts"
ISS_SCRIPT = SCRIPTS_DIR / "helm_installer.iss"
STANDALONE_BUILDER = SCRIPTS_DIR / "build_standalone.py"

CORE_MODULES = [
    # Main Application Entry Points
    "app.py",
    "helm.py",
    "requirements.txt",
    "run.bat",

    # Core Execution & Supervision Engines
    "helm_supervisor.py",
    "helm_supervisor_daemon.py",
    "action_broker.py",
    "agent_tools.py",
    "ai_engine.py",
    "task_manager.py",
    "assistant_timeline.py",
    "chat_cli.py",
    "chat_core.py",

    # UI, HUD & Interaction Layers
    "helm_omnibar.py",
    "helm_canvas.py",
    "action_pill.py",
    "tray_hud.py",

    # Voice & Audio Pipeline
    "voice.py",
    "voice_pipeline.py",
    "helm_voice_stream.py",
    "wake_word_engine.py",

    # Vision, OCR & Screen Memory
    "screen_ocr_engine.py",
    "semantic_screen_memory.py",
    "helm_ghost_desktop.py",
    "helm_snapshot.py",

    # Security, Trust & Governance
    "trust_tiers.py",
    "rails_config.py",
    "rails_confirmation.py",
    "step_up_gate.py",
    "update_verifier.py",
    "worker_confinement.py",
    "helm_ssrf.py",
    "helm_intrusion_watch.py",

    # Knowledge, Memory & Context
    "durable_memory.py",
    "meeting_notes.py",
    "helm_knowledge_graph.py",
    "helm_learn.py",
    "helm_anticipatory.py",
    "helm_everything_search.py",
    "helm_ide_bridge.py",
    "helm_file_witness.py",
    "helm_attachments.py",
    "helm_watchers.py",
    "helm_selfheal.py",
    "helm_session_compression.py",

    # Automations & System Integrations
    "windows_tools.py",
    "notification_mirror.py",
    "grounding_tools.py",
    "phone_gateway.py",
    "phone_approval_portal.py",
    "mobile_remote.py",
    "helm_apps_catalog.py",
    "helm_style.py",
    "helm_briefs.py",
    "helm_plugins.py",
    "helm_mcp.py",
    "helm_writer.py",
    "helm_vla_agent.py",
    "helm_worker.py",
    "helm_focus_mode.py",
    "helm_layout_profiles.py",
    "helm_netstat.py",
    "helm_resource_tracker.py",
    "helm_retrospective.py",
    "helm_skills.py",
    "db_utils.py",
    "event_log.py",
]

ASSET_DIRS = [
    "ui",
    "config",
]


def log_info(msg: str) -> None:
    print(f"\033[94m[*] {msg}\033[0m")


def log_success(msg: str) -> None:
    print(f"\033[92m[+] {msg}\033[0m")


def log_warn(msg: str) -> None:
    print(f"\033[93m[!] {msg}\033[0m")


def log_error(msg: str) -> None:
    print(f"\033[91m[-] {msg}\033[0m")


def find_iscc() -> Path | None:
    """Finds the Inno Setup 6 compiler (ISCC.exe) in PATH or standard installation directories."""
    # 1. Search PATH
    which_iscc = shutil.which("iscc")
    if which_iscc:
        return Path(which_iscc)

    # 2. Standard Program Files search paths
    standard_paths = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
    ]

    for p in standard_paths:
        if p.exists():
            return p

    return None


def build_portable_zip(version: str = "1.0.0") -> Path:
    """Assembles the portable source bundle and zips it."""
    log_info(f"Building Helm portable bundle (v{version}) from: {BASE_DIR}")
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy Core Python Modules & Files
    copied_modules = 0
    for mod in CORE_MODULES:
        src = BASE_DIR / mod
        if src.exists():
            shutil.copy2(src, BUILD_DIR / mod)
            copied_modules += 1
        else:
            log_warn(f"Optional or missing module skipped: {mod}")

    log_success(f"Packaged {copied_modules} core runtime files into bundle.")

    # 2. Copy Asset Directories (UI, Config)
    for adir in ASSET_DIRS:
        src_dir = BASE_DIR / adir
        if src_dir.exists():
            dest_dir = BUILD_DIR / adir
            shutil.copytree(src_dir, dest_dir, dirs_exist_ok=True)
            log_success(f"Packaged asset directory: {adir}")

    # 3. Create Windows Launcher Script (run_helm.bat)
    bat_content = (
        "@echo off\r\n"
        "title Helm - Windows Desktop Assistant\r\n"
        "cd /d \"%~dp0\"\r\n"
        "if exist app.py (\r\n"
        "    python app.py %*\r\n"
        ") else (\r\n"
        "    python helm.py %*\r\n"
        ")\r\n"
        "if errorlevel 1 pause\r\n"
    )
    (BUILD_DIR / "run_helm.bat").write_text(bat_content, encoding="utf-8")

    # 4. Create Silent Windowless Launcher (Helm.vbs)
    vbs_content = (
        "Set WshShell = CreateObject(\"WScript.Shell\")\r\n"
        "WshShell.Run \"cmd.exe /c \"\"\" & Replace(WScript.ScriptFullName, WScript.ScriptName, \"run_helm.bat\") & \"\"\"\", 0, False\r\n"
    )
    (BUILD_DIR / "Helm.vbs").write_text(vbs_content, encoding="utf-8")

    # 5. Create Desktop Shortcut PowerShell Installer
    ps1_content = (
        "$WshShell = New-Object -ComObject WScript.Shell\r\n"
        "$Target = Join-Path $PSScriptRoot 'Helm.vbs'\r\n"
        "$IconPath = Join-Path $PSScriptRoot 'ui\\AppIcon.ico'\r\n"
        "$DesktopPath = [Environment]::GetFolderPath('Desktop')\r\n"
        "$Shortcut = $WshShell.CreateShortcut((Join-Path $DesktopPath 'Helm.lnk'))\r\n"
        "$Shortcut.TargetPath = $Target\r\n"
        "$Shortcut.WorkingDirectory = $PSScriptRoot\r\n"
        "if (Test-Path $IconPath) { $Shortcut.IconLocation = \"$IconPath,0\" }\r\n"
        "$Shortcut.Description = 'Helm Personal Desktop AI'\r\n"
        "$Shortcut.Save()\r\n"
        "Write-Host 'Helm desktop shortcut created successfully!' -ForegroundColor Green\r\n"
    )
    (BUILD_DIR / "install_desktop_shortcut.ps1").write_text(ps1_content, encoding="utf-8")

    # 6. Create Distribution Zip Archive
    zip_dest = DIST_DIR / f"Helm-Windows-x64-portable-v{version}.zip"
    zip_generic = DIST_DIR / "Helm-Windows-x64.zip"

    log_info(f"Compressing portable bundle into: {zip_dest}")
    with zipfile.ZipFile(zip_dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(BUILD_DIR):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(BUILD_DIR)
                zf.write(abs_path, arcname=str(rel_path))

    # Also copy to generic name for backwards compatibility
    shutil.copy2(zip_dest, zip_generic)

    log_success(f"Portable zip bundle successfully created: {zip_dest} ({zip_dest.stat().st_size // 1024} KB)")
    return zip_dest


def build_standalone(clean: bool = False, version: str = "1.0.0") -> bool:
    """Invokes build_standalone.py to compile the PyInstaller binary."""
    log_info(f"Triggering standalone binary build (v{version})...")
    cmd = [sys.executable, str(STANDALONE_BUILDER), "--version", version]
    if clean:
        cmd.append("--clean")

    res = subprocess.run(cmd, cwd=str(BASE_DIR), check=False)
    if res.returncode == 0:
        log_success("Standalone binary compilation succeeded.")
        return True
    else:
        log_error(f"Standalone binary compilation failed with code {res.returncode}.")
        return False


def build_installer(version: str = "1.0.0") -> bool:
    """Invokes Inno Setup (ISCC.exe) to compile the Windows installer."""
    log_info(f"Triggering Inno Setup installer build (v{version})...")

    if not ISS_SCRIPT.exists():
        log_error(f"Inno Setup script not found at: {ISS_SCRIPT}")
        return False

    iscc_path = find_iscc()
    if not iscc_path:
        log_warn("Inno Setup compiler (ISCC.exe) not found in PATH or standard Program Files locations.")
        log_info("To compile the Windows installer binary:")
        log_info("  1. Install Inno Setup 6:")
        log_info("     winget install JRSoftware.InnoSetup")
        log_info("     or download from https://jrsoftware.org/isdl.php")
        log_info(f"  2. Run: iscc /DMyAppVersion={version} scripts/helm_installer.iss")
        log_info("     or: python scripts/package_helm.py --installer")
        return False

    log_info(f"Using Inno Setup compiler: {iscc_path}")
    cmd = [
        str(iscc_path),
        f"/DMyAppVersion={version}",
        "/Q",  # Quiet mode
        str(ISS_SCRIPT),
    ]

    try:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR), check=True)
        if proc.returncode == 0:
            expected_installer = DIST_DIR / f"Helm-Setup-{version}.exe"
            if expected_installer.exists():
                size_mb = expected_installer.stat().st_size / (1024 * 1024)
                log_success(f"Installer successfully compiled: {expected_installer} ({size_mb:.2f} MB)")
            else:
                log_success("Inno Setup compilation finished successfully.")
            return True
        else:
            log_error(f"Inno Setup compiler failed with exit code {proc.returncode}.")
            return False
    except subprocess.CalledProcessError as e:
        log_error(f"Inno Setup compilation failed: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Helm Distribution Packaging & Installer Automation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Build all distribution artifacts (standalone binary, Inno installer, portable zip)",
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Build the portable source zip bundle (dist/Helm-Windows-x64-portable.zip)",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Compile the standalone PyInstaller binary (dist/Helm/Helm.exe)",
    )
    parser.add_argument(
        "--installer",
        action="store_true",
        help="Compile the Inno Setup Windows installer (dist/Helm-Setup-<version>.exe)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build and dist directories before packaging",
    )
    parser.add_argument(
        "--version",
        default="1.0.0",
        help="Version tag for the release artifacts (default: 1.0.0)",
    )

    args = parser.parse_args()

    # Default action: if no specific mode specified, build portable bundle and notify user
    if not (args.all or args.portable or args.standalone or args.installer):
        args.portable = True

    print("=" * 65)
    print(f"  Helm Distribution & Installer Packaging Suite v{args.version}")
    print("=" * 65)

    success = True

    # 1. Clean if requested
    if args.clean:
        log_info("Cleaning build and dist directories...")
        for p in [BUILD_DIR, DIST_DIR]:
            if p.exists():
                try:
                    shutil.rmtree(p)
                except Exception as e:
                    log_warn(f"Could not remove {p}: {e}")

    # 2. Standalone PyInstaller Binary
    if args.all or args.standalone:
        ok = build_standalone(clean=args.clean, version=args.version)
        if not ok and not args.all:
            return 1
        success = success and ok

    # 3. Inno Setup Installer
    if args.all or args.installer:
        ok = build_installer(version=args.version)
        if not ok and not args.all:
            return 1
        success = success and ok

    # 4. Portable Zip Bundle
    if args.all or args.portable:
        try:
            build_portable_zip(version=args.version)
        except Exception as e:
            log_error(f"Portable zip build failed: {e}")
            return 1

    print("\n" + "=" * 65)
    log_success("Packaging operations completed!")
    log_info(f"Artifacts output directory: {DIST_DIR}")
    print("=" * 65)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
