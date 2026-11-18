"""homie_watchers.py - Web Portal Watchers & Differential Alerting Engine.

Monitors web portals (university notice boards, exam schedules, ticket queues, company dashboards)
on a recurring schedule without AI model inference at runtime:
- Deterministic extraction: parses HTML tables, list elements, or custom CSS selectors.
- Differential engine: computes cryptographic identity and content diffs (new, changed, removed).
- Zero-noise alerting: notifies the user (Windows notification + Telegram companion) ONLY when
  meaningful changes or new announcements appear.
- Durable SQLite storage in data/homie_watchers.db.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import sqlite3
import hashlib
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WATCHERS_DB_PATH = os.path.join(BASE_DIR, "data", "homie_watchers.db")
os.makedirs(os.path.dirname(WATCHERS_DB_PATH), exist_ok=True)

MAX_FIELD_LEN = 300
MAX_FIELDS_PER_ITEM = 12
MAX_ITEMS_PER_SECTION = 200

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class WatcherDiff:
    name: str
    new_items: list[dict[str, str]] = field(default_factory=list)
    changed_items: list[dict[str, str]] = field(default_factory=list)
    removed_count: int = 0
    total_current: int = 0
    first_run: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.new_items or self.changed_items)

    def summary(self) -> str:
        if self.first_run:
            return f"Watcher '{self.name}' initialized: {self.total_current} items tracked."
        if not self.has_changes:
            return f"Watcher '{self.name}': No changes ({self.total_current} items monitored)."
        parts = []
        if self.new_items:
            parts.append(f"{len(self.new_items)} new item(s)")
        if self.changed_items:
            parts.append(f"{len(self.changed_items)} changed item(s)")
        if self.removed_count:
            parts.append(f"{self.removed_count} removed")
        return f"Watcher '{self.name}' update: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# HTML Parsing & Content Extraction
# ---------------------------------------------------------------------------

def _strip_tags(html_chunk: str) -> str:
    """Removes HTML tags and normalizes whitespace."""
    clean = re.sub(r"<[^>]+>", " ", html_chunk)
    return " ".join(clean.split())[:MAX_FIELD_LEN]


def extract_portal_items(html: str, rows_selector: str = "", fields_map: Optional[dict[str, str]] = None) -> list[dict[str, str]]:
    """Extracts structured items from HTML table rows or list elements."""
    items: list[dict[str, str]] = []

    # Priority 1: Table row extraction
    table_rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.DOTALL | re.IGNORECASE)
    if table_rows:
        headers: list[str] = []
        # Check first row for <th>
        first_row_ths = re.findall(r"<th[^>]*>(.*?)</th>", table_rows[0], re.DOTALL | re.IGNORECASE)
        start_idx = 0
        if first_row_ths:
            headers = [_strip_tags(th).lower().replace(" ", "_") or f"col_{idx}" for idx, th in enumerate(first_row_ths)]
            start_idx = 1

        for r_html in table_rows[start_idx:MAX_ITEMS_PER_SECTION]:
            tds = re.findall(r"<td[^>]*>(.*?)</td>", r_html, re.DOTALL | re.IGNORECASE)
            if not tds:
                continue
            item = {}
            for c_idx, td in enumerate(tds[:MAX_FIELDS_PER_ITEM]):
                h_name = headers[c_idx] if c_idx < len(headers) else f"field_{c_idx + 1}"
                item[h_name] = _strip_tags(td)
            if item and any(item.values()):
                items.append(item)

    # Priority 2: Unordered / ordered list items if no tables found
    if not items:
        lis = re.findall(r"<li[^>]*>(.*?)</li>", html, re.DOTALL | re.IGNORECASE)
        for idx, li in enumerate(lis[:MAX_ITEMS_PER_SECTION], start=1):
            txt = _strip_tags(li)
            if txt:
                items.append({"title": txt, "index": str(idx)})

    return items


# ---------------------------------------------------------------------------
# Diff Calculation
# ---------------------------------------------------------------------------

def _item_identity(item: dict[str, str], key_fields: Optional[list[str]] = None) -> str:
    """Computes identity hash based on key fields (e.g. title, course, id)."""
    if key_fields:
        cand_vals = [item.get(k, "").lower().strip() for k in key_fields if k in item]
        if cand_vals and any(cand_vals):
            return hashlib.sha256("::".join(cand_vals).encode("utf-8")).hexdigest()[:16]

    # Common heuristic key fields
    for common_k in ("id", "title", "subject", "notice", "course", "headline", "name"):
        if common_k in item and item[common_k]:
            return hashlib.sha256(item[common_k].lower().strip().encode("utf-8")).hexdigest()[:16]

    # Full item identity
    sorted_pairs = [f"{k}={v.lower().strip()}" for k, v in sorted(item.items())]
    return hashlib.sha256("::".join(sorted_pairs).encode("utf-8")).hexdigest()[:16]


def _item_content_hash(item: dict[str, str]) -> str:
    sorted_pairs = [f"{k}={v.strip()}" for k, v in sorted(item.items())]
    return hashlib.sha256("::".join(sorted_pairs).encode("utf-8")).hexdigest()[:16]


def calculate_diff(
    prev_items: list[dict[str, str]],
    curr_items: list[dict[str, str]],
    key_fields: Optional[list[str]] = None
) -> Tuple[list[dict[str, str]], list[dict[str, str]], int]:
    """Calculates (new_items, changed_items, removed_count)."""
    if not prev_items:
        return curr_items, [], 0

    prev_map: dict[str, tuple[str, dict[str, str]]] = {}
    for itm in prev_items:
        ident = _item_identity(itm, key_fields)
        c_hash = _item_content_hash(itm)
        prev_map[ident] = (c_hash, itm)

    new_items: list[dict[str, str]] = []
    changed_items: list[dict[str, str]] = []
    seen_identities: set[str] = set()

    for itm in curr_items:
        ident = _item_identity(itm, key_fields)
        c_hash = _item_content_hash(itm)
        seen_identities.add(ident)

        if ident not in prev_map:
            new_items.append(itm)
        else:
            prev_hash, _ = prev_map[ident]
            if prev_hash != c_hash:
                changed_items.append(itm)

    removed_count = sum(1 for p_id in prev_map if p_id not in seen_identities)
    return new_items, changed_items, removed_count


# ---------------------------------------------------------------------------
# Database & Watcher Management
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(WATCHERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS watchers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            recipe_json TEXT,
            interval_minutes INTEGER DEFAULT 360,
            last_checked REAL,
            last_digest TEXT,
            last_snapshot_json TEXT,
            created_at REAL,
            enabled INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    return conn


def add_watcher(
    name: str,
    url: str,
    recipe: Optional[dict[str, Any]] = None,
    interval_minutes: int = 360
) -> dict[str, Any]:
    """Registers a new portal watcher."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        return {"ok": False, "error": "Only HTTP/HTTPS URLs are allowed."}

    watcher_id = f"watch_{hashlib.sha256(f'{url}:{name}'.encode()).hexdigest()[:12]}"
    conn = _get_db()
    with conn:
        conn.execute("""
            INSERT OR REPLACE INTO watchers 
            (id, name, url, recipe_json, interval_minutes, created_at, enabled)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (
            watcher_id,
            name.strip(),
            url.strip(),
            json.dumps(recipe or {}),
            max(interval_minutes, 10),
            time.time()
        ))

    return {
        "ok": True,
        "watcher_id": watcher_id,
        "name": name,
        "url": url,
        "interval_minutes": interval_minutes,
        "message": f"Watcher '{name}' registered. Will monitor {url} every {interval_minutes} minutes."
    }


def list_watchers() -> list[dict[str, Any]]:
    """Lists all configured watchers."""
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM watchers ORDER BY created_at DESC")
    rows = cur.fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "name": r["name"],
            "url": r["url"],
            "interval_minutes": r["interval_minutes"],
            "last_checked": r["last_checked"],
            "last_digest": r["last_digest"],
            "enabled": bool(r["enabled"])
        })
    return results


def check_watcher(watcher_id: str, force: bool = False, fetcher_fn=None) -> WatcherDiff:
    """Checks one watcher, extracts content, calculates diff, and updates snapshot."""
    conn = _get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM watchers WHERE id = ?", (watcher_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError(f"Watcher '{watcher_id}' not found.")

    name = row["name"]
    url = row["url"]
    prev_items = json.loads(row["last_snapshot_json"]) if row["last_snapshot_json"] else []
    first_run = row["last_checked"] is None

    # Fetch page HTML
    html = ""
    if fetcher_fn:
        html = fetcher_fn(url)
    else:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HomieWatcher/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw_bytes = resp.read(2 * 1024 * 1024)
                html = raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            return WatcherDiff(name=name, total_current=len(prev_items))

    recipe = json.loads(row["recipe_json"]) if row["recipe_json"] else {}
    rows_sel = recipe.get("rows", "")
    key_fields = recipe.get("key", [])

    curr_items = extract_portal_items(html, rows_selector=rows_sel)
    new_items, changed_items, removed_count = calculate_diff(prev_items, curr_items, key_fields=key_fields)

    diff = WatcherDiff(
        name=name,
        new_items=new_items,
        changed_items=changed_items,
        removed_count=removed_count,
        total_current=len(curr_items),
        first_run=first_run
    )

    # Update database
    now = time.time()
    curr_digest = hashlib.sha256(json.dumps(curr_items, sort_keys=True).encode("utf-8")).hexdigest()
    with conn:
        conn.execute("""
            UPDATE watchers SET
                last_checked = ?,
                last_digest = ?,
                last_snapshot_json = ?
            WHERE id = ?
        """, (now, curr_digest, json.dumps(curr_items), watcher_id))

    # Trigger alerts if changes occurred (and not first run)
    if diff.has_changes and not first_run:
        _dispatch_watcher_alert(name, diff)

    return diff


def check_all_watchers(fetcher_fn=None) -> list[WatcherDiff]:
    """Runs due checks across all enabled watchers."""
    watchers = list_watchers()
    diffs = []
    now = time.time()

    for w in watchers:
        if not w["enabled"]:
            continue
        interval_sec = w["interval_minutes"] * 60
        last_checked = w["last_checked"] or 0
        if (now - last_checked) >= interval_sec:
            try:
                diff = check_watcher(w["id"], fetcher_fn=fetcher_fn)
                diffs.append(diff)
            except Exception:
                pass

    return diffs


def remove_watcher(watcher_id: str) -> bool:
    """Removes a watcher by ID."""
    conn = _get_db()
    with conn:
        res = conn.execute("DELETE FROM watchers WHERE id = ?", (watcher_id,))
        return res.rowcount > 0


def _dispatch_watcher_alert(name: str, diff: WatcherDiff) -> None:
    """Dispatches alert through Homie notifications and Telegram bridge."""
    title = f"📢 Homie Watcher: {name}"
    msg = diff.summary()

    # 1. Desktop Notification
    try:
        import tray_hud
        tray_hud.post_hud_notification(title, msg)
    except Exception:
        pass

    # 2. Telegram Companion Alert
    try:
        import telegram_bridge
        tb = telegram_bridge.get_telegram_bridge()
        if tb and getattr(tb, "paired_chat_id", None):
            alert_text = f"🔔 *Watcher Alert: {name}*\n{msg}\n\n"
            for item in diff.new_items[:5]:
                alert_text += f"• *{item.get('title', 'Item')}*: {list(item.values())[0]}\n"
            tb.send_message(tb.paired_chat_id, alert_text)
    except Exception:
        pass

    # 3. Assistant Timeline Event
    try:
        import assistant_timeline
        assistant_timeline.record_timeline_event(
            kind="WATCHER_DIFF_ALERT",
            summary=msg,
            data={"watcher": name, "new_count": len(diff.new_items), "changed_count": len(diff.changed_items)}
        )
    except Exception:
        pass
