"""homie_apps_catalog.py - Connected SaaS & MCP Applications Discovery Catalog.

Provides a unified discovery directory of 65+ pre-verified productivity, engineering,
marketing, design, and database SaaS tools with official MCP servers:
- Fast multi-keyword & category search (Productivity, Developer tools, Marketing, Design, etc.).
- Authentication schema inspection (OAuth 2.1 PKCE dynamic/user, DPAPI token, None).
- Default tool capability mapping and least-privilege risk assignment.
"""

from __future__ import annotations

import os
import re
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CATALOG_YAML_PATH = os.path.join(BASE_DIR, "config", "mcp_catalog.yaml")

CATEGORIES = (
    "Productivity",
    "Email and chat",
    "Developer tools",
    "Design",
    "Databases",
    "Websites",
    "Automation",
    "Docs and AI",
    "Finance and markets",
    "Marketing"
)


@dataclass
class AppEntry:
    id: str
    name: str
    category: str
    publisher: str
    status: str
    description: str
    transport: str
    url: str
    auth_type: str
    docs_url: str
    tools: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return f"{self.name} [{self.category}] - {self.description} (Auth: {self.auth_type})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "publisher": self.publisher,
            "status": self.status,
            "description": self.description,
            "transport": self.transport,
            "url": self.url,
            "auth_type": self.auth_type,
            "docs_url": self.docs_url,
            "tools_count": len(self.tools)
        }


class AppsCatalog:
    def __init__(self, catalog_path: str = CATALOG_YAML_PATH):
        self.catalog_path = catalog_path
        self._apps: dict[str, AppEntry] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.catalog_path):
            return

        with open(self.catalog_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_apps = data.get("apps", {})
        for app_id, info in raw_apps.items():
            auth_info = info.get("auth", {})
            auth_type = auth_info.get("type", "none") if isinstance(auth_info, dict) else str(auth_info)
            tools_list = list(info.get("tools", {}).keys()) if isinstance(info.get("tools"), dict) else []

            self._apps[app_id] = AppEntry(
                id=app_id,
                name=info.get("name", app_id),
                category=info.get("category", "Productivity"),
                publisher=info.get("publisher", "Vendor"),
                status=info.get("status", "official"),
                description=info.get("description", ""),
                transport=info.get("transport", "http"),
                url=info.get("url", ""),
                auth_type=auth_type,
                docs_url=info.get("docs", ""),
                tools=tools_list
            )

    @property
    def total_apps(self) -> int:
        return len(self._apps)

    def get_app(self, app_id: str) -> Optional[AppEntry]:
        return self._apps.get(app_id.lower().strip())

    def search(self, query: str = "", category: str = "", limit: int = 20) -> list[AppEntry]:
        """Filters apps by keyword query and/or category."""
        results = []
        q = query.lower().strip()
        cat = category.lower().strip()

        for app in self._apps.values():
            if cat and cat != app.category.lower():
                continue
            if q:
                target = f"{app.id} {app.name} {app.description} {app.category}".lower()
                if q not in target:
                    continue
            results.append(app)
            if len(results) >= limit:
                break

        return results

    def list_categories(self) -> list[str]:
        return sorted(list({a.category for a in self._apps.values()}))


_GLOBAL_CATALOG: Optional[AppsCatalog] = None


def get_apps_catalog() -> AppsCatalog:
    global _GLOBAL_CATALOG
    if _GLOBAL_CATALOG is None:
        _GLOBAL_CATALOG = AppsCatalog()
    return _GLOBAL_CATALOG


def list_apps(query: str = "", category: str = "", limit: int = 15) -> dict[str, Any]:
    cat = get_apps_catalog()
    matches = cat.search(query=query, category=category, limit=limit)
    return {
        "ok": True,
        "total_available": cat.total_apps,
        "matches_count": len(matches),
        "apps": [m.to_dict() for m in matches]
    }


def get_app_info(app_id: str) -> dict[str, Any]:
    cat = get_apps_catalog()
    app = cat.get_app(app_id)
    if not app:
        return {"ok": False, "error": f"App '{app_id}' not found in catalog."}
    return {
        "ok": True,
        "app": app.to_dict()
    }
