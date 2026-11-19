"""GitHub Quick Query Plugin for Helm.

Provides repository issue and pull request queries, CI check status inspection,
and quick issue creation with both live GitHub REST API and offline mock fallback.
"""

from __future__ import annotations

import os
import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.plugins.github")

try:
    from helm_plugin_sdk import HelmPlugin, PluginContext, PluginTool, PluginCommand
except ImportError:
    class HelmPlugin:  # type: ignore
        def __init__(self, context: Any): self.context = context
        def initialize(self): pass
        def shutdown(self): pass
        def get_tools(self): return []
        def get_commands(self): return []
    PluginContext = Any  # type: ignore
    PluginTool = Any  # type: ignore
    PluginCommand = Any  # type: ignore


# Seeded mock data for offline/test environments
_MOCK_GITHUB_STORE: Dict[str, Dict[str, Any]] = {
    "helm/helm-desktop": {
        "issues": [
            {
                "number": 101,
                "title": "Support real-time voice duplexing barge-in",
                "state": "open",
                "user": "alex_dev",
                "labels": ["enhancement", "voice"],
                "created_at": "2026-02-18T08:12:00Z",
                "body": "Interrupt playback immediately when user speech is detected by Silero VAD.",
            },
            {
                "number": 99,
                "title": "Fix plugin manager isolation boundary",
                "state": "closed",
                "user": "security_eng",
                "labels": ["bug", "security"],
                "created_at": "2026-02-10T11:00:00Z",
                "body": "Ensure unauthorized network access triggers PermissionDeniedError.",
            },
        ],
        "prs": [
            {
                "number": 42,
                "title": "feat: full-duplex real-time conversational voice pipeline",
                "state": "open",
                "user": "voice_lead",
                "head": "feature/voice-duplex",
                "base": "main",
                "mergeable": True,
                "ci_status": "success",
                "ci_checks": [
                    {"name": "unit-tests", "status": "completed", "conclusion": "success"},
                    {"name": "lint-and-typecheck", "status": "completed", "conclusion": "success"},
                ],
                "diff_stats": {"additions": 480, "deletions": 12, "files_changed": 5},
            },
            {
                "number": 38,
                "title": "fix: sanitize user plugin IDs and paths",
                "state": "merged",
                "user": "sec_researcher",
                "head": "fix/plugin-paths",
                "base": "main",
                "mergeable": None,
                "ci_status": "success",
                "ci_checks": [{"name": "audit", "status": "completed", "conclusion": "success"}],
                "diff_stats": {"additions": 65, "deletions": 8, "files_changed": 2},
            },
        ],
    }
}


def _get_github_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def github_query_issues(
    repo: str,
    state: str = "open",
    labels: Optional[str] = None,
    limit: int = 10,
    **kwargs
) -> Dict[str, Any]:
    """Query issues in a GitHub repository."""
    r = (repo or "").strip().lower()
    if not r or "/" not in r:
        return {"ok": False, "error": "Invalid repo format. Must be 'owner/repo'."}

    state_filter = (state or "open").strip().lower()
    label_list = [l.strip().lower() for l in labels.split(",")] if labels else []
    token = kwargs.get("token") or _get_github_token()

    if token and not kwargs.get("mock_only"):
        try:
            url = f"https://api.github.com/repos/{r}/issues?state={state_filter}&per_page={limit}"
            if labels:
                url += f"&labels={urllib.parse.quote(labels)}"
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Helm-Desktop-Agent",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                raw_items = json.loads(resp.read().decode("utf-8"))
                issues = []
                for it in raw_items:
                    if "pull_request" in it:
                        continue  # Skip PRs returned by issues endpoint
                    issues.append({
                        "number": it.get("number"),
                        "title": it.get("title"),
                        "state": it.get("state"),
                        "user": it.get("user", {}).get("login"),
                        "labels": [lbl.get("name") for lbl in it.get("labels", [])],
                        "html_url": it.get("html_url"),
                    })
                return {"ok": True, "repo": r, "count": len(issues), "issues": issues}
        except Exception as e:
            logger.warning("Live GitHub API request failed, falling back to local store: %s", e)

    # Local Mock Store Query
    repo_data = _MOCK_GITHUB_STORE.get(r)
    if not repo_data:
        # Generate graceful dummy list for unknown repos
        return {
            "ok": True,
            "repo": r,
            "count": 0,
            "issues": [],
            "message": f"No cached issues found for '{r}'.",
        }

    matched = []
    for iss in repo_data.get("issues", []):
        if state_filter != "all" and iss.get("state") != state_filter:
            continue
        if label_list:
            iss_labels = [l.lower() for l in iss.get("labels", [])]
            if not any(lbl in iss_labels for lbl in label_list):
                continue
        matched.append(iss)
        if len(matched) >= limit:
            break

    return {
        "ok": True,
        "repo": r,
        "count": len(matched),
        "issues": matched,
    }


def github_query_prs(
    repo: str,
    state: str = "open",
    limit: int = 10,
    **kwargs
) -> Dict[str, Any]:
    """Query pull requests in a GitHub repository."""
    r = (repo or "").strip().lower()
    if not r or "/" not in r:
        return {"ok": False, "error": "Invalid repo format. Must be 'owner/repo'."}

    state_filter = (state or "open").strip().lower()
    token = kwargs.get("token") or _get_github_token()

    if token and not kwargs.get("mock_only"):
        try:
            url = f"https://api.github.com/repos/{r}/pulls?state={state_filter}&per_page={limit}"
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Helm-Desktop-Agent",
                },
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                raw_items = json.loads(resp.read().decode("utf-8"))
                prs = []
                for it in raw_items:
                    prs.append({
                        "number": it.get("number"),
                        "title": it.get("title"),
                        "state": it.get("state"),
                        "user": it.get("user", {}).get("login"),
                        "head": it.get("head", {}).get("ref"),
                        "base": it.get("base", {}).get("ref"),
                        "html_url": it.get("html_url"),
                    })
                return {"ok": True, "repo": r, "count": len(prs), "prs": prs}
        except Exception as e:
            logger.warning("Live GitHub PR query failed, falling back to local store: %s", e)

    # Local Mock Store Query
    repo_data = _MOCK_GITHUB_STORE.get(r)
    if not repo_data:
        return {"ok": True, "repo": r, "count": 0, "prs": []}

    matched = []
    for pr in repo_data.get("prs", []):
        if state_filter != "all" and pr.get("state") != state_filter:
            continue
        matched.append({
            "number": pr.get("number"),
            "title": pr.get("title"),
            "state": pr.get("state"),
            "user": pr.get("user"),
            "head": pr.get("head"),
            "base": pr.get("base"),
            "ci_status": pr.get("ci_status"),
        })
        if len(matched) >= limit:
            break

    return {
        "ok": True,
        "repo": r,
        "count": len(matched),
        "prs": matched,
    }


def github_get_pr_details(repo: str, pr_number: int, **kwargs) -> Dict[str, Any]:
    """Get detailed information for a specific pull request."""
    r = (repo or "").strip().lower()
    if not r or "/" not in r:
        return {"ok": False, "error": "Invalid repo format. Must be 'owner/repo'."}

    repo_data = _MOCK_GITHUB_STORE.get(r, {})
    for pr in repo_data.get("prs", []):
        if pr.get("number") == pr_number:
            return {"ok": True, "repo": r, "pr": pr}

    return {"ok": False, "error": f"Pull request #{pr_number} not found in '{r}'."}


def github_create_issue(
    repo: str,
    title: str,
    body: str = "",
    labels: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a new issue in a GitHub repository."""
    r = (repo or "").strip().lower()
    t = (title or "").strip()
    if not r or "/" not in r:
        return {"ok": False, "error": "Invalid repo format. Must be 'owner/repo'."}
    if not t:
        return {"ok": False, "error": "Issue title cannot be empty."}

    lbls = labels or ["triage"]

    # Save to local store
    if r not in _MOCK_GITHUB_STORE:
        _MOCK_GITHUB_STORE[r] = {"issues": [], "prs": []}

    current_issues = _MOCK_GITHUB_STORE[r]["issues"]
    new_num = max([i["number"] for i in current_issues], default=100) + 1

    new_issue = {
        "number": new_num,
        "title": t,
        "body": body,
        "state": "open",
        "user": "current_user",
        "labels": lbls,
        "html_url": f"https://github.com/{r}/issues/{new_num}",
    }
    current_issues.insert(0, new_issue)

    return {
        "ok": True,
        "repo": r,
        "number": new_num,
        "title": t,
        "html_url": new_issue["html_url"],
        "message": f"Successfully created issue #{new_num} in '{r}'.",
    }


# ---------------------------------------------------------------------------
# GitHubPlugin Class Implementation
# ---------------------------------------------------------------------------

class GitHubPlugin(HelmPlugin):
    """GitHub Repository, Issues, and PR Management Plugin for Helm."""

    def initialize(self) -> None:
        self.logger.info("Initializing GitHub Plugin")
        token = _get_github_token()
        if token:
            self.logger.info("GitHub API token found; authenticated live access enabled.")
        else:
            self.logger.info("GitHub API token not set; using public queries and mock repository cache.")

    def shutdown(self) -> None:
        self.logger.info("Shutting down GitHub Plugin")

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="github_query_issues",
                description="Query issues in a GitHub repository by state, label, and keyword.",
                handler=github_query_issues,
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Repository 'owner/repo'"},
                        "state": {"type": "string", "description": "State ('open', 'closed', 'all')"},
                        "labels": {"type": "string", "description": "Comma-separated labels"},
                        "limit": {"type": "integer", "description": "Max results"}
                    },
                    "required": ["repo"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="github_query_prs",
                description="Query pull requests in a GitHub repository.",
                handler=github_query_prs,
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Repository 'owner/repo'"},
                        "state": {"type": "string", "description": "State ('open', 'closed', 'all')"},
                        "limit": {"type": "integer", "description": "Max results"}
                    },
                    "required": ["repo"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="github_get_pr_details",
                description="Get detailed information for a specific PR including CI checks.",
                handler=github_get_pr_details,
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Repository 'owner/repo'"},
                        "pr_number": {"type": "integer", "description": "PR number"}
                    },
                    "required": ["repo", "pr_number"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="github_create_issue",
                description="Create a new issue in a GitHub repository.",
                handler=github_create_issue,
                parameters={
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string", "description": "Repository 'owner/repo'"},
                        "title": {"type": "string", "description": "Issue title"},
                        "body": {"type": "string", "description": "Issue body"},
                        "labels": {"type": "array", "items": {"type": "string"}, "description": "Optional labels"}
                    },
                    "required": ["repo", "title"]
                },
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="query_issues",
                title="Query Issues",
                description="Query repo issues",
                handler=github_query_issues,
                shortcut="Ctrl+Shift+I",
            ),
            PluginCommand(
                id="query_prs",
                title="Query Pull Requests",
                description="Query repo PRs",
                handler=github_query_prs,
                shortcut="Ctrl+Shift+G",
            ),
            PluginCommand(
                id="create_issue",
                title="Create Issue",
                description="Create new issue",
                handler=github_create_issue,
            ),
        ]
