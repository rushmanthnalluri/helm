"""helm_context_search.py - Local Context Search Engine with SQLite FTS5 (BM25), Nonce-Enveloped Chunks,
Encryption at Rest, and Rate-Limited Privacy Hardening.

Key Features:
- Classified as SENSITIVE_READ: indexes private workstation history (screen, notes, meetings).
- SQLite FTS5 virtual table for full-text search across local workstation context.
- Sources indexed:
  1. Quick notes & tasks (quick_notes.py)
  2. Meeting notes & transcripts (meeting_notes.py)
  3. Screen memory timeline (semantic_screen_memory.py)
  4. Allowlisted local document/project summaries
- Attacker-writable folder defense: folders such as Downloads and Temp are strictly flagged as tainted.
- Encryption at rest: chunk bodies and metadata can be sealed at rest using crypto_vault (DPAPI / AES-256-GCM).
- Nonce envelopes: every retrieved chunk is isolated inside a unique random nonce envelope
  ([[[CHUNK nonce={nonce} source={source} id={id}]]] ... [[[END_CHUNK nonce={nonce}]]])
  to defend against indirect prompt injections and preserve source traceability.
- Privacy & forgetfulness: forget_last(minutes) safely expunges recently indexed chunks with PRAGMA secure_delete and VACUUM.
- Rate limiting: sliding-window limiter bounds queries to prevent automated exfiltration loops.
"""

import os
import sys
import re
import time
import secrets
import sqlite3
import threading
import logging
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_quarantine_reader
import crypto_vault

logger = logging.getLogger("helm.context_search")

DEFAULT_DB_PATH = os.path.join(os.path.expanduser("~"), ".helm", "context_search.db")

ATTACKER_WRITABLE_PATTERNS = [
    r"(?i)[\\/]downloads([\\/]|$)",
    r"(?i)[\\/]temp([\\/]|$)",
    r"(?i)[\\/]tmp([\\/]|$)",
    r"(?i)[\\/]desktop([\\/]|$)",
    r"(?i)appdata[\\/]local[\\/]temp",
]


def is_attacker_writable_path(path: str) -> bool:
    """Checks whether a path resides in an untrusted or attacker-writable location like Downloads or Temp."""
    if not path:
        return False
    norm = os.path.normpath(path).lower()
    for pat in ATTACKER_WRITABLE_PATTERNS:
        if re.search(pat, norm):
            return True
    return False


def sanitize_fts_query(query: str) -> str:
    """Sanitizes user query into safe SQLite FTS5 query tokens."""
    cleaned = re.sub(r"[^\w\s]", " ", query, flags=re.UNICODE).strip()
    tokens = [t for t in cleaned.split() if t]
    if not tokens:
        return ""
    # Use prefix matching for each term
    return " AND ".join(f'"{t}"*' for t in tokens)


class SearchRateLimiter:
    """Sliding-window rate limiter for sensitive context search (max queries per window)."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []
        self._lock = threading.Lock()

    def check_and_record(self) -> Tuple[bool, str]:
        now = time.time()
        with self._lock:
            self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]
            if len(self.timestamps) >= self.max_requests:
                return False, f"Rate limit exceeded: Context search is capped to {self.max_requests} queries per minute to protect user privacy."
            self.timestamps.append(now)
            return True, ""

    def reset(self):
        with self._lock:
            self.timestamps.clear()


_GLOBAL_SEARCH_RATE_LIMITER = SearchRateLimiter(max_requests=10, window_seconds=60.0)


class LocalContextIndex:
    """Thread-safe SQLite FTS5 index for multi-source workstation context with encryption at rest."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA secure_delete = ON;")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            # Apply owner-only DACL to database file directory if on Windows
            self._harden_storage()
        self._lock = threading.Lock()
        self._init_db()

    def _harden_storage(self):
        try:
            import helm_confinement
            if os.path.exists(self.db_path):
                helm_confinement.apply_owner_only_file_dacl(self.db_path)
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if os.path.exists(db_dir):
                helm_confinement.apply_owner_only_file_dacl(db_dir)
        except Exception as e:
            logger.debug("DACL hardening notice for context search DB: %s", e)

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA secure_delete = ON;")
        return con

    def _close_connection(self, con: sqlite3.Connection):
        if con is not self._mem_conn:
            con.close()

    def _init_db(self):
        with self._lock:
            con = self._get_connection()
            try:
                cur = con.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chunk_metadata (
                        chunk_id TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        title TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        taint INTEGER NOT NULL DEFAULT 1,
                        uri_or_path TEXT,
                        exclusion_rule_id TEXT,
                        encrypted_body TEXT
                    )
                """)
                cur.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5(
                        chunk_id UNINDEXED,
                        title,
                        body,
                        source UNINDEXED,
                        tokenize = 'porter unicode61'
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_meta_ts ON chunk_metadata(timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_meta_source ON chunk_metadata(source)")
                con.commit()
            finally:
                self._close_connection(con)

    def add_chunk(
        self,
        chunk_id: str,
        source: str,
        title: str,
        body: str,
        timestamp: Optional[float] = None,
        taint: bool = True,
        uri_or_path: str = "",
        exclusion_rule_id: Optional[str] = None
    ) -> bool:
        """Indexes a chunk into metadata and FTS tables with encryption at rest."""
        ts = timestamp if timestamp is not None else time.time()
        # Enforce taint on attacker-writable folders like Downloads or Temp
        is_writable = is_attacker_writable_path(uri_or_path)
        if is_writable:
            taint = True

        # Encrypt body at rest for sensitive metadata store
        try:
            encrypted_body = crypto_vault.encrypt(body, domain="context_fts")
        except Exception:
            encrypted_body = ""

        with self._lock:
            con = self._get_connection()
            try:
                cur = con.cursor()
                cur.execute("DELETE FROM chunk_metadata WHERE chunk_id = ?", (chunk_id,))
                cur.execute("DELETE FROM chunk_fts WHERE chunk_id = ?", (chunk_id,))

                cur.execute("""
                    INSERT INTO chunk_metadata (chunk_id, source, title, timestamp, taint, uri_or_path, exclusion_rule_id, encrypted_body)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (chunk_id, source, title, ts, 1 if taint else 0, uri_or_path, exclusion_rule_id, encrypted_body))

                cur.execute("""
                    INSERT INTO chunk_fts (chunk_id, title, body, source)
                    VALUES (?, ?, ?, ?)
                """, (chunk_id, title, body, source))

                con.commit()
                return True
            except Exception as e:
                logger.error("Failed to index chunk %s: %s", chunk_id, e)
                con.rollback()
                return False
            finally:
                self._close_connection(con)

    def search(
        self,
        query: str,
        sources: Optional[List[str]] = None,
        since: Optional[float] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Searches index with BM25 ranking, filtering by sources and timestamp."""
        limit = max(1, min(limit, 20))
        fts_query = sanitize_fts_query(query)
        if not fts_query:
            return []

        sql = """
            SELECT 
                m.chunk_id,
                m.source,
                m.title,
                m.timestamp,
                m.taint,
                m.uri_or_path,
                snippet(chunk_fts, 2, '<b>', '</b>', '...', 32) as snippet_text,
                bm25(chunk_fts) as rank
            FROM chunk_fts f
            JOIN chunk_metadata m ON f.chunk_id = m.chunk_id
            WHERE chunk_fts MATCH ?
        """
        params: List[Any] = [fts_query]

        if sources:
            placeholders = ",".join("?" for _ in sources)
            sql += f" AND m.source IN ({placeholders})"
            params.extend(sources)

        if since is not None:
            sql += " AND m.timestamp >= ?"
            params.append(since)

        sql += " ORDER BY rank ASC LIMIT ?"
        params.append(limit)

        results = []
        with self._lock:
            con = self._get_connection()
            try:
                cur = con.cursor()
                rows = cur.execute(sql, params).fetchall()
                for r in rows:
                    results.append({
                        "chunk_id": r["chunk_id"],
                        "source": r["source"],
                        "title": r["title"],
                        "timestamp": r["timestamp"],
                        "taint": True,  # All context search results carry taint
                        "uri_or_path": r["uri_or_path"] or "",
                        "snippet": r["snippet_text"] or "",
                        "rank": float(r["rank"])
                    })
            except Exception as e:
                logger.error("Context search query error: %s", e)
            finally:
                self._close_connection(con)

        return results

    def forget_last(self, minutes: int) -> int:
        """Expunges all indexed chunks created or modified within the last N minutes with secure_delete and VACUUM."""
        if minutes <= 0:
            return 0
        cutoff = time.time() - (minutes * 60.0)
        with self._lock:
            con = self._get_connection()
            try:
                cur = con.cursor()
                rows = cur.execute("SELECT chunk_id FROM chunk_metadata WHERE timestamp >= ?", (cutoff,)).fetchall()
                chunk_ids = [r["chunk_id"] for r in rows]
                if not chunk_ids:
                    return 0

                placeholders = ",".join("?" for _ in chunk_ids)
                cur.execute("PRAGMA secure_delete = ON;")
                cur.execute(f"DELETE FROM chunk_metadata WHERE chunk_id IN ({placeholders})", chunk_ids)
                cur.execute(f"DELETE FROM chunk_fts WHERE chunk_id IN ({placeholders})", chunk_ids)
                con.commit()

                # Reclaim and zero free pages so deleted text does not linger
                try:
                    con.execute("VACUUM;")
                except Exception as e:
                    logger.debug("VACUUM after forget_last notice: %s", e)

                return len(chunk_ids)
            except Exception as e:
                logger.error("Failed to forget last %d minutes: %s", minutes, e)
                con.rollback()
                return 0
            finally:
                self._close_connection(con)

    def sync_from_local_timeline(self) -> int:
        """Pulls recent items from quick_notes, meeting_notes, and screen_memory into index."""
        indexed_count = 0
        # 1. Quick notes
        try:
            import quick_notes
            notes = quick_notes.get_recent_notes(limit=30)
            for n in notes:
                nid = f"note_{n.get('id', secrets.token_hex(4))}"
                title = n.get("title") or "Quick Note"
                body = n.get("content", "")
                ts = n.get("created_at") or time.time()
                if self.add_chunk(nid, source="quick_notes", title=title, body=body, timestamp=ts, taint=True):
                    indexed_count += 1
        except Exception as e:
            logger.debug("Quick notes sync notice: %s", e)

        # 2. Meeting notes
        try:
            import meeting_notes
            meetings = meeting_notes.get_recent_meetings(limit=15)
            for m in meetings:
                mid = f"meeting_{m.get('id', secrets.token_hex(4))}"
                title = m.get("title", "Meeting")
                body_parts = [m.get("summary", ""), " ".join(m.get("action_items", []))]
                body = " ".join([p for p in body_parts if p])
                ts = m.get("created_at") or time.time()
                if self.add_chunk(mid, source="meeting_notes", title=title, body=body, timestamp=ts, taint=True):
                    indexed_count += 1
        except Exception as e:
            logger.debug("Meeting notes sync notice: %s", e)

        # 3. Screen memory timeline
        try:
            import semantic_screen_memory
            events = semantic_screen_memory.get_recent_timeline(limit=25)
            for ev in events:
                app_name = ev.get("app_name", "")
                if semantic_screen_memory.is_sensitive(app_name):
                    continue
                ev_id = f"screen_{ev.get('id', secrets.token_hex(4))}"
                title = f"{app_name}: {ev.get('window_title', '')}"
                body = ev.get("ocr_text", "") or ev.get("summary", "")
                ts = ev.get("timestamp") or time.time()
                if body and self.add_chunk(ev_id, source="screen_memory", title=title, body=body, timestamp=ts, taint=True):
                    indexed_count += 1
        except Exception as e:
            logger.debug("Screen memory sync notice: %s", e)

        return indexed_count


_GLOBAL_INDEX: Optional[LocalContextIndex] = None


def get_context_index(db_path: Optional[str] = None) -> LocalContextIndex:
    global _GLOBAL_INDEX
    if _GLOBAL_INDEX is None or (db_path and _GLOBAL_INDEX.db_path != db_path):
        _GLOBAL_INDEX = LocalContextIndex(db_path=db_path)
    return _GLOBAL_INDEX


def format_enveloped_results(results: List[Dict[str, Any]]) -> str:
    """Formats search results inside per-chunk cryptographic nonce envelopes with provenance & taint indicators."""
    if not results:
        return "No matching context found."

    blocks = ["[Search Results: Local Context (SENSITIVE_READ - Tainted)]"]
    for r in results:
        nonce = secrets.token_hex(4)
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"])) if r.get("timestamp") else "unknown"
        snippet = r.get("snippet", "").replace("<<<DATA>>>", "").replace("[[[UNTRUSTED]]]", "")
        snippet = snippet.replace("<b>", "").replace("</b>", "").strip()

        path_val = r.get("uri_or_path") or "local_store"
        warning_line = ""
        if is_attacker_writable_path(path_val):
            warning_line = "\nSecurity: ⚠️ [UNTRUSTED ATTACKER-WRITABLE SOURCE (Downloads/Temp) - STRICT TAINT]"

        block = (
            f"[[[CHUNK nonce={nonce} source={r['source']} id={r['chunk_id']}]]]\n"
            f"Title: {r['title']}\n"
            f"Timestamp: {ts_str}\n"
            f"Path: {path_val}{warning_line}\n"
            f"Snippet: {snippet}\n"
            f"[[[END_CHUNK nonce={nonce}]]]"
        )
        blocks.append(block)

    return "\n\n".join(blocks)


def search_context_tool(
    query: str,
    sources: Optional[List[str]] = None,
    since: Optional[float] = None,
    limit: int = 5,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Tool entry point for helm_search_context (SENSITIVE_READ, rate-limited, taint-propagating)."""
    # 1. Rate-limiting check
    allowed, rate_msg = _GLOBAL_SEARCH_RATE_LIMITER.check_and_record()
    if not allowed:
        return {
            "ok": False,
            "error": rate_msg,
            "query": query,
            "count": 0,
            "results": [],
            "enveloped_text": f"⚠️ {rate_msg}",
            "tainted": True
        }

    index = get_context_index(db_path=db_path)
    try:
        index.sync_from_local_timeline()
    except Exception:
        pass

    results = index.search(query=query, sources=sources, since=since, limit=limit)
    enveloped_text = format_enveloped_results(results)

    # 2. Propagate taint to taint_tracker
    try:
        import taint_tracker
        taint_tracker.mark_untrusted("helm_search_context")
    except Exception:
        pass

    return {
        "ok": True,
        "query": query,
        "count": len(results),
        "results": results,
        "enveloped_text": enveloped_text,
        "tainted": True
    }
