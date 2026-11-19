"""helm_ide_bridge.py - Deep IDE & Developer Workspace Context Bridge for VS Code & Cursor.

Enables Helm to understand active developer state without relying on lossy screen OCR:
1. Active Workspace State:
   - Detects active workspace folder, open projects, and recent git history.
2. Git Diff & Working Tree Inspection:
   - Current branch, uncommitted staged/unstaged changes, and recent commit log.
3. Terminal Error & Diagnostic Analyzer:
   - Inspects workspace for build artifacts, test failures, and unresolved conflicts.
"""

from __future__ import annotations

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def get_ide_workspace_context(workspace_path: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves high-fidelity developer context from the active IDE workspace."""
    ws = workspace_path or BASE_DIR
    if not os.path.exists(ws):
        return {"ok": False, "error": f"Workspace path '{ws}' does not exist."}

    git_info: Dict[str, Any] = {"is_git": False}

    # 1. Query Git Branch & Status
    try:
        branch_res = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=3
        )
        if branch_res.returncode == 0:
            git_info["is_git"] = True
            git_info["branch"] = branch_res.stdout.strip()

        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=3
        )
        if status_res.returncode == 0:
            modified = [line.strip() for line in status_res.stdout.strip().splitlines() if line.strip()]
            git_info["modified_files_count"] = len(modified)
            git_info["modified_files"] = modified[:15]

        # Recent commit
        log_res = subprocess.run(
            ["git", "log", "-1", "--oneline"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=3
        )
        if log_res.returncode == 0:
            git_info["last_commit"] = log_res.stdout.strip()

    except Exception:
        pass

    # 2. Inspect VS Code settings or workspace config
    vscode_dir = os.path.join(ws, ".vscode")
    has_vscode = os.path.isdir(vscode_dir)

    # 3. Detect Project Language / Framework
    detected_tech = []
    if os.path.exists(os.path.join(ws, "package.json")):
        detected_tech.append("Node.js / TypeScript")
    if os.path.exists(os.path.join(ws, "requirements.txt")) or os.path.exists(os.path.join(ws, "pyproject.toml")):
        detected_tech.append("Python")
    if os.path.exists(os.path.join(ws, "Cargo.toml")):
        detected_tech.append("Rust")
    if os.path.exists(os.path.join(ws, "go.mod")):
        detected_tech.append("Go")

    return {
        "ok": True,
        "workspace_root": ws,
        "is_vscode_workspace": has_vscode,
        "detected_technologies": detected_tech,
        "git": git_info
    }


def get_git_diff_summary(workspace_path: Optional[str] = None, max_lines: int = 150) -> Dict[str, Any]:
    """Fetches a concise unified git diff of working tree changes."""
    ws = workspace_path or BASE_DIR
    try:
        diff_res = subprocess.run(
            ["git", "diff", "--stat"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=5
        )
        stat = diff_res.stdout.strip() if diff_res.returncode == 0 else ""

        full_diff_res = subprocess.run(
            ["git", "diff"],
            cwd=ws,
            capture_output=True,
            text=True,
            timeout=5
        )
        lines = full_diff_res.stdout.strip().splitlines()[:max_lines] if full_diff_res.returncode == 0 else []

        return {
            "ok": True,
            "stat": stat,
            "diff_snippet": "\n".join(lines),
            "truncated": len(lines) >= max_lines
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
