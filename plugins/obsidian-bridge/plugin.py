"""Obsidian Vault Bridge Plugin for Helm.

Enables bi-directional knowledge ingestion, note searching, and daily note logging
directly into a user's local Obsidian vault.
"""

from __future__ import annotations

import os
import re
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.plugins.obsidian")


def _get_vault_path() -> Path:
    custom = os.environ.get("OBSIDIAN_VAULT_PATH")
    if custom:
        p = Path(custom).expanduser().resolve()
        if p.exists():
            return p
    # Default fallback path
    default = Path.home() / "Documents" / "Obsidian Vault"
    default.mkdir(parents=True, exist_ok=True)
    return default


def obsidian_search_notes(query: str) -> Dict[str, Any]:
    """Searches markdown files across the Obsidian vault for matching text."""
    if not query:
        return {"status": "error", "error": "Query string is required"}

    vault = _get_vault_path()
    matches = []
    q_lower = query.lower()

    for md_file in vault.rglob("*.md"):
        # Skip .obsidian configuration folder
        if ".obsidian" in md_file.parts:
            continue
        try:
            content = md_file.read_text(encoding="utf-8", errors="ignore")
            title = md_file.stem
            if q_lower in title.lower() or q_lower in content.lower():
                # Extract surrounding snippet
                idx = content.lower().find(q_lower)
                snippet = ""
                if idx != -1:
                    start = max(0, idx - 60)
                    end = min(len(content), idx + 120)
                    snippet = "..." + content[start:end].replace("\n", " ") + "..."
                else:
                    snippet = content[:150].replace("\n", " ")
                
                matches.append({
                    "title": title,
                    "rel_path": str(md_file.relative_to(vault)),
                    "snippet": snippet,
                })
        except Exception:
            pass

        if len(matches) >= 10:
            break

    return {"status": "success", "vault": str(vault), "query": query, "count": len(matches), "results": matches}


def obsidian_append_daily(content: str) -> Dict[str, Any]:
    """Appends text or an action item to today's daily note in Obsidian."""
    if not content:
        return {"status": "error", "error": "Content cannot be empty"}

    vault = _get_vault_path()
    daily_dir = vault / "Daily Notes"
    daily_dir.mkdir(parents=True, exist_ok=True)

    today_str = datetime.now().strftime("%Y-%m-%d")
    daily_file = daily_dir / f"{today_str}.md"

    now_time = datetime.now().strftime("%H:%M")
    entry = f"\n- **{now_time}** (via Helm): {content.strip()}\n"

    try:
        with open(daily_file, "a", encoding="utf-8") as f:
            f.write(entry)
        return {
            "status": "success",
            "file": str(daily_file.relative_to(vault)),
            "appended": content.strip(),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def obsidian_get_backlinks(note_name: str) -> Dict[str, Any]:
    """Finds all notes that link to [[note_name]] within the vault."""
    if not note_name:
        return {"status": "error", "error": "note_name is required"}

    vault = _get_vault_path()
    clean_target = note_name.replace(".md", "").strip()
    pattern = re.compile(rf"\[\[{re.escape(clean_target)}(\|.*?)?\]\]", re.IGNORECASE)

    backlinks = []
    for md_file in vault.rglob("*.md"):
        if ".obsidian" in md_file.parts or md_file.stem.lower() == clean_target.lower():
            continue
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore")
            if pattern.search(text):
                backlinks.append({
                    "referencing_note": md_file.stem,
                    "path": str(md_file.relative_to(vault)),
                })
        except Exception:
            pass

    return {
        "status": "success",
        "target_note": clean_target,
        "backlinks_count": len(backlinks),
        "backlinks": backlinks,
    }
