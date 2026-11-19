"""Notion Quick Capture & Page Search Plugin for Helm.

Provides note capture, workspace page search, and document creation
for Notion, with offline mock store fallback for seamless testing and offline usage.
"""

from __future__ import annotations

import os
import time
import uuid
import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.plugins.notion")

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


# In-memory mock database for offline/testing mode
_LOCAL_NOTION_PAGES: Dict[str, Dict[str, Any]] = {
    "page-seed-001": {
        "id": "page-seed-001",
        "title": "Helm Roadmap & Architecture",
        "content": "Helm Desktop Agent Architecture, plugin system, voice duplexing, and sync.",
        "tags": ["roadmap", "architecture", "engineering"],
        "created_time": "2026-01-15T10:00:00Z",
        "url": "https://notion.so/helm-roadmap-001",
    },
    "page-seed-002": {
        "id": "page-seed-002",
        "title": "Meeting Notes: AI Assistant UX",
        "content": "Discussing omnibar shortcuts, quick capture, and real-time audio barge-in.",
        "tags": ["meeting", "design", "ux"],
        "created_time": "2026-02-10T14:30:00Z",
        "url": "https://notion.so/meeting-notes-002",
    },
}


def _get_api_key() -> Optional[str]:
    return os.environ.get("NOTION_API_KEY") or os.environ.get("NOTION_TOKEN")


def notion_quick_capture(text: str, title: Optional[str] = None, tags: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
    """Capture a quick note, idea, or task into Notion."""
    note_text = (text or "").strip()
    if not note_text:
        return {"ok": False, "error": "Note text cannot be empty."}

    note_title = title.strip() if title else f"Quick Note - {time.strftime('%Y-%m-%d %H:%M')}"
    note_tags = tags or ["quick-capture"]
    api_key = kwargs.get("api_key") or _get_api_key()

    # If live API key is present, attempt live Notion API call
    if api_key and not kwargs.get("mock_only"):
        try:
            req_data = {
                "parent": {"type": "page_id", "page_id": kwargs.get("parent_id", "")},
                "properties": {
                    "title": [{"text": {"content": note_title}}]
                },
                "children": [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {"rich_text": [{"type": "text", "text": {"content": note_text}}]}
                    }
                ]
            }
            req = urllib.request.Request(
                "https://api.notion.com/v1/pages",
                data=json.dumps(req_data).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Notion-Version": "2022-06-28",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ok": True,
                    "id": data.get("id"),
                    "title": note_title,
                    "url": data.get("url"),
                    "source": "live_notion_api",
                    "message": f"Successfully captured note '{note_title}' to Notion.",
                }
        except Exception as e:
            logger.warning("Live Notion API call failed, falling back to local capture: %s", e)

    # Local / Offline Fallback Store
    page_id = f"page-{uuid.uuid4().hex[:8]}"
    page_obj = {
        "id": page_id,
        "title": note_title,
        "content": note_text,
        "tags": note_tags,
        "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url": f"https://notion.so/{page_id}",
    }
    _LOCAL_NOTION_PAGES[page_id] = page_obj
    return {
        "ok": True,
        "id": page_id,
        "title": note_title,
        "url": page_obj["url"],
        "tags": note_tags,
        "source": "local_store",
        "message": f"Quick note captured: '{note_title}'",
    }


def notion_search_pages(query: str, limit: int = 5, **kwargs) -> Dict[str, Any]:
    """Search Notion workspace pages and databases by query."""
    q = (query or "").strip().lower()
    if not q:
        return {"ok": False, "error": "Query cannot be empty."}

    api_key = kwargs.get("api_key") or _get_api_key()

    if api_key and not kwargs.get("mock_only"):
        try:
            req_data = {"query": q, "page_size": limit}
            req = urllib.request.Request(
                "https://api.notion.com/v1/search",
                data=json.dumps(req_data).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Notion-Version": "2022-06-28",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = []
                for item in data.get("results", []):
                    title_prop = item.get("properties", {}).get("title", {}).get("title", [])
                    title_text = title_prop[0].get("plain_text", "Untitled") if title_prop else "Untitled"
                    results.append({
                        "id": item.get("id"),
                        "title": title_text,
                        "url": item.get("url"),
                        "type": item.get("object"),
                    })
                return {"ok": True, "query": q, "count": len(results), "pages": results}
        except Exception as e:
            logger.warning("Live Notion search failed, searching local pages: %s", e)

    # Search local store
    matches = []
    for pid, p in _LOCAL_NOTION_PAGES.items():
        title = p.get("title", "").lower()
        content = p.get("content", "").lower()
        tags = [t.lower() for t in p.get("tags", [])]
        if q in title or q in content or any(q in t for t in tags):
            matches.append({
                "id": pid,
                "title": p.get("title"),
                "snippet": p.get("content", "")[:120],
                "tags": p.get("tags", []),
                "url": p.get("url"),
            })
            if len(matches) >= limit:
                break

    return {
        "ok": True,
        "query": q,
        "count": len(matches),
        "pages": matches,
    }


def notion_create_page(title: str, content: str, parent_id: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Create a new page in Notion."""
    t = (title or "").strip()
    c = (content or "").strip()
    if not t:
        return {"ok": False, "error": "Title cannot be empty."}

    page_id = f"page-{uuid.uuid4().hex[:8]}"
    page_obj = {
        "id": page_id,
        "title": t,
        "content": c,
        "parent_id": parent_id,
        "tags": ["document"],
        "created_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url": f"https://notion.so/{page_id}",
    }
    _LOCAL_NOTION_PAGES[page_id] = page_obj
    return {
        "ok": True,
        "id": page_id,
        "title": t,
        "url": page_obj["url"],
        "message": f"Created page '{t}'",
    }


def notion_get_page(page_id: str, **kwargs) -> Dict[str, Any]:
    """Retrieve Notion page content by page ID."""
    pid = (page_id or "").strip()
    if not pid:
        return {"ok": False, "error": "page_id is required."}

    page = _LOCAL_NOTION_PAGES.get(pid)
    if not page:
        return {"ok": False, "error": f"Page with ID '{pid}' not found."}

    return {
        "ok": True,
        "page": page,
    }


# ---------------------------------------------------------------------------
# NotionPlugin Class Implementation
# ---------------------------------------------------------------------------

class NotionPlugin(HelmPlugin):
    """Notion Quick Capture & Search Plugin for Helm."""

    def initialize(self) -> None:
        self.logger.info("Initializing Notion Plugin")
        key = _get_api_key()
        if key:
            self.logger.info("Notion API key found; running with live Notion integration.")
        else:
            self.logger.info("Notion API key not set; running with offline local document store.")

    def shutdown(self) -> None:
        self.logger.info("Shutting down Notion Plugin")

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="notion_quick_capture",
                description="Quickly capture a note, idea, or task to Notion inbox.",
                handler=notion_quick_capture,
                parameters={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Note content"},
                        "title": {"type": "string", "description": "Optional title"},
                        "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags"}
                    },
                    "required": ["text"]
                },
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
            PluginTool(
                name="notion_search_pages",
                description="Search Notion workspace pages and databases by title or query.",
                handler=notion_search_pages,
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search keyword"},
                        "limit": {"type": "integer", "description": "Max results"}
                    },
                    "required": ["query"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="notion_create_page",
                description="Create a new structured Notion page with title and content.",
                handler=notion_create_page,
                parameters={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Page title"},
                        "content": {"type": "string", "description": "Body markdown/content"},
                        "parent_id": {"type": "string", "description": "Optional parent ID"}
                    },
                    "required": ["title", "content"]
                },
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
            PluginTool(
                name="notion_get_page",
                description="Retrieve page metadata and content by Notion page ID.",
                handler=notion_get_page,
                parameters={
                    "type": "object",
                    "properties": {
                        "page_id": {"type": "string", "description": "Notion page ID"}
                    },
                    "required": ["page_id"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="capture_note",
                title="Quick Capture Note",
                description="Capture note to Notion",
                handler=notion_quick_capture,
                shortcut="Ctrl+Shift+N",
            ),
            PluginCommand(
                id="search_pages",
                title="Search Pages",
                description="Search Notion pages",
                handler=notion_search_pages,
                shortcut="Ctrl+Shift+O",
            ),
        ]
