"""GitHub PR & Issues Tracker Plugin for Helm.

Enables developers to query pull requests, check CI statuses, and review diffs
using the GitHub REST API or local 'gh' CLI credentials.
"""

from __future__ import annotations

import os
import json
import logging
import subprocess
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

logger = logging.getLogger("helm.plugins.github")


def _get_auth_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Helm-Desktop-Assistant/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def github_list_prs(repo: str = "", state: str = "open") -> Dict[str, Any]:
    """Lists open pull requests for the repository."""
    if not repo:
        # Try finding current git repo remote
        try:
            rem = subprocess.check_output(
                ["git", "remote", "get-url", "origin"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).strip()
            if "github.com" in rem:
                part = rem.split("github.com")[-1].lstrip("/:").rstrip(".git")
                repo = part
        except Exception:
            pass

    if not repo:
        return {
            "error": "No repository specified and unable to detect git origin.",
            "prs": [],
        }

    url = f"https://api.github.com/repos/{repo}/pulls?state={state}&per_page=10"
    req = urllib.request.Request(url, headers=_get_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            prs = []
            for item in data:
                prs.append({
                    "number": item.get("number"),
                    "title": item.get("title"),
                    "user": item.get("user", {}).get("login"),
                    "created_at": item.get("created_at"),
                    "url": item.get("html_url"),
                    "draft": item.get("draft", False),
                })
            return {"repo": repo, "count": len(prs), "prs": prs}
    except urllib.error.HTTPError as e:
        return {"error": f"GitHub API error: HTTP {e.code}", "repo": repo, "prs": []}
    except Exception as e:
        return {"error": str(e), "repo": repo, "prs": []}


def github_review_diff(repo: str = "", pr_id: int = 1) -> Dict[str, Any]:
    """Returns summarized diff and changed files for a pull request."""
    if not repo:
        return {"error": "Repository ('owner/repo') is required."}

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_id}/files"
    req = urllib.request.Request(url, headers=_get_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            files_data = json.loads(resp.read().decode("utf-8"))
            summary = []
            for f in files_data[:15]:
                summary.append({
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "additions": f.get("additions"),
                    "deletions": f.get("deletions"),
                    "patch_snippet": (f.get("patch") or "")[:300],
                })
            return {"repo": repo, "pr_id": pr_id, "files_count": len(files_data), "changed_files": summary}
    except Exception as e:
        return {"error": str(e), "repo": repo, "pr_id": pr_id}


def github_ci_status(repo: str = "", ref: str = "main") -> Dict[str, Any]:
    """Checks the commit check runs and CI status for a given ref."""
    if not repo:
        return {"error": "Repository ('owner/repo') is required."}

    url = f"https://api.github.com/repos/{repo}/commits/{ref}/check-runs"
    req = urllib.request.Request(url, headers=_get_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            runs = []
            for r in data.get("check_runs", []):
                runs.append({
                    "name": r.get("name"),
                    "status": r.get("status"),
                    "conclusion": r.get("conclusion"),
                    "html_url": r.get("html_url"),
                })
            return {"repo": repo, "ref": ref, "check_runs_count": len(runs), "runs": runs}
    except Exception as e:
        return {"error": str(e), "repo": repo, "ref": ref}
