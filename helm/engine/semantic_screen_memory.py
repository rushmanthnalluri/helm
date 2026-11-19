"""Helm Semantic Screen Memory & Recall.
Inspired by Screenpipe and Rewind AI, this provides a local-first, privacy-aware
timeline memory layer for Windows:
- Hardware-accelerated OCR extraction via Windows.Media.Ocr / screen_ocr_engine
- Full-text search with SQLite FTS5 (screen_memory_fts MATCH ? ORDER BY rank) and LIKE fallback
- Periodically or on-event indexes active foreground window title, process, and text
- Privacy filters to automatically exclude banking, password managers, and incognito windows
- Natural language recall: "What was I reading 20 minutes ago?", "Find tracking number on screen"
"""

import os
import sys
import time
import logging
import threading
import sqlite3
import contextlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import db_utils
import windows_tools
import crypto_vault

# Attempt import of hardware OCR engine
try:
    import screen_ocr_engine
except ImportError:
    screen_ocr_engine = None

logger = logging.getLogger("helm.screen_memory")

# The monitor is started by the desktop app during normal startup. Keep these
# lifecycle flags initialized so that the first start does not fail before the
# hotkey listener or UI can be brought up.
_monitor_running = False
_monitor_thread = None

SENSITIVE_KEYWORDS = [
    "password", "1password", "bitwarden", "lastpass", "keepass", "bank",
    "banking", "incognito", "private browsing", "credit card", "security code"
]

EXCLUDED_APPS = {
    "1password.exe", "bitwarden.exe", "keepass.exe", "lastpass.exe", "tor.exe"
}

_FTS5_AVAILABLE: Optional[bool] = None
_VEC_AVAILABLE: Optional[bool] = None

# Embedding model singleton configuration (all-MiniLM-L6-v2, 384-dim)
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384
_EMBED_MODEL = None
_EMBED_MODEL_LOCK = threading.Lock()


def get_embedding_model():
    """Module-level singleton that lazy-loads SentenceTransformer('all-MiniLM-L6-v2') once."""
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        with _EMBED_MODEL_LOCK:
            if _EMBED_MODEL is None:
                try:
                    from sentence_transformers import SentenceTransformer
                    _EMBED_MODEL = SentenceTransformer(EMBEDDING_MODEL_NAME)
                    logger.info("Loaded SentenceTransformer model '%s' successfully.", EMBEDDING_MODEL_NAME)
                except Exception as e:
                    logger.warning("Failed to initialize SentenceTransformer model '%s': %s", EMBEDDING_MODEL_NAME, e)
                    return None
    return _EMBED_MODEL


def _load_vec_extension(conn: sqlite3.Connection) -> bool:
    """Loads the sqlite-vec extension into the SQLite connection."""
    global _VEC_AVAILABLE
    if _VEC_AVAILABLE is False:
        return False
    try:
        import sqlite_vec
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        _VEC_AVAILABLE = True
        return True
    except Exception as e:
        logger.debug("sqlite-vec load extension failed: %s", e)
        _VEC_AVAILABLE = False
        return False


@contextlib.contextmanager
def _get_db(db_path: Optional[str] = None):
    """Context manager wrapping db_utils.get_db with sqlite-vec extension loaded."""
    with db_utils.get_db(db_path) as conn:
        _load_vec_extension(conn)
        yield conn


def _encode_text_to_vec(text: str) -> Optional[bytes]:
    """Generates a 384-dim float32 embedding and serializes it for sqlite-vec storage."""
    if not text or not text.strip():
        return None
    try:
        model = get_embedding_model()
        if model is None:
            return None
        emb = model.encode(text)
        if hasattr(emb, "tolist"):
            emb = emb.tolist()
        import sqlite_vec
        return sqlite_vec.serialize_float32(emb)
    except Exception as e:
        logger.debug("Failed to generate embedding for text: %s", e)
        return None


def init_screen_memory_db():
    """Initializes screen_timeline table, FTS5 virtual table, sqlite-vec vec0 table, and indices."""
    global _FTS5_AVAILABLE, _VEC_AVAILABLE
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS screen_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                proc_name TEXT NOT NULL,
                window_title TEXT NOT NULL,
                text_content TEXT,
                summary TEXT,
                perceptual_hash TEXT,
                is_sensitive INTEGER DEFAULT 0
            );
        """)
        try:
            conn.execute("ALTER TABLE screen_timeline ADD COLUMN perceptual_hash TEXT;")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE screen_timeline ADD COLUMN is_sensitive INTEGER DEFAULT 0;")
        except Exception:
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_screen_ts ON screen_timeline(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_screen_proc ON screen_timeline(proc_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_screen_phash ON screen_timeline(perceptual_hash);")

        # 1. Create SQLite FTS5 Virtual Table for full-text search
        try:
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS screen_memory_fts USING fts5(
                    proc_name,
                    window_title,
                    text_content,
                    summary
                );
            """)

            # Trigger to automatically clean up FTS entries on row deletion
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_screen_timeline_ad 
                AFTER DELETE ON screen_timeline 
                BEGIN 
                    DELETE FROM screen_memory_fts WHERE rowid = old.id; 
                END;
            """)
            _FTS5_AVAILABLE = True

            # Backfill FTS index if table has existing records but FTS is empty
            try:
                fts_count = conn.execute("SELECT count(*) FROM screen_memory_fts").fetchone()[0]
                timeline_count = conn.execute("SELECT count(*) FROM screen_timeline").fetchone()[0]
                if fts_count == 0 and timeline_count > 0:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, proc_name, window_title, text_content, summary FROM screen_timeline")
                    for row in cursor.fetchall():
                        r_id, proc, title, enc_text, summary = row[0], row[1], row[2], row[3], row[4]
                        plain_text = _decrypt_row_text(enc_text)
                        cursor.execute("""
                            INSERT OR REPLACE INTO screen_memory_fts (rowid, proc_name, window_title, text_content, summary)
                            VALUES (?, ?, ?, ?, ?)
                        """, (r_id, proc or "", title or "", plain_text or "", summary or ""))
            except Exception as backfill_err:
                logger.debug("FTS5 backfill warning: %s", backfill_err)

        except Exception as e:
            logger.warning("FTS5 not supported or table initialization failed (%s); fallback to LIKE will be used", e)
            _FTS5_AVAILABLE = False

        # 2. Create sqlite-vec vec0 Virtual Table for vector embeddings
        if _load_vec_extension(conn):
            try:
                conn.execute(f"""
                    CREATE VIRTUAL TABLE IF NOT EXISTS screen_memory_vec USING vec0(
                        embedding float[{EMBEDDING_DIM}] distance_metric=cosine
                    );
                """)
                _VEC_AVAILABLE = True

                # Backfill vector index if table has existing records but vec table is empty
                try:
                    vec_count = conn.execute("SELECT count(*) FROM screen_memory_vec").fetchone()[0]
                    timeline_count = conn.execute("SELECT count(*) FROM screen_timeline").fetchone()[0]
                    if vec_count == 0 and timeline_count > 0:
                        cursor = conn.cursor()
                        cursor.execute("SELECT id, proc_name, window_title, text_content, summary FROM screen_timeline")
                        rows_to_backfill = cursor.fetchall()
                        for row in rows_to_backfill:
                            r_id, proc, title, enc_text, summary = row[0], row[1], row[2], row[3], row[4]
                            plain_text = _decrypt_row_text(enc_text)
                            text_to_embed = " ".join(filter(None, [title, plain_text, summary])) or proc or ""
                            if text_to_embed:
                                vec_bytes = _encode_text_to_vec(text_to_embed)
                                if vec_bytes:
                                    cursor.execute("""
                                        INSERT OR REPLACE INTO screen_memory_vec (rowid, embedding)
                                        VALUES (?, ?)
                                    """, (r_id, vec_bytes))
                except Exception as vec_backfill_err:
                    logger.debug("sqlite-vec backfill warning: %s", vec_backfill_err)

            except Exception as e:
                logger.warning("sqlite-vec virtual table init failed (%s); vector search will be disabled", e)
                _VEC_AVAILABLE = False

        conn.commit()


# Safe initialization on import
try:
    init_screen_memory_db()
except Exception as _init_err:
    logger.debug("Database initialization deferred: %s", _init_err)


def add_excluded_app(proc_name: str):
    """Adds a process name to the exclusion blacklist."""
    if proc_name:
        EXCLUDED_APPS.add(proc_name.lower().strip())


def get_excluded_apps() -> set:
    """Returns the set of excluded application process names."""
    return set(EXCLUDED_APPS)


def is_sensitive(title: str, proc_name: str, text: str = "") -> bool:
    """Evaluates privacy filters to exclude sensitive windows and processes."""
    proc_clean = (proc_name or "").lower().strip()
    if proc_clean in EXCLUDED_APPS or any(app in proc_clean for app in EXCLUDED_APPS):
        return True
    combined = f"{title} {proc_name} {text}".lower()
    return any(k in combined for k in SENSITIVE_KEYWORDS)


def _decrypt_row_text(stored_text: Optional[str]) -> str:
    """Safely decrypts stored text using the cryptographic vault."""
    if not stored_text:
        return ""
    try:
        return crypto_vault.decrypt(stored_text)
    except Exception:
        return stored_text


def compute_perceptual_hash(image_or_bytes: Any) -> str:
    """Computes a 64-bit difference perceptual hash (dHash) for an image.
    Accepts PIL Image, bytes, file path, or falls back to a deterministic content hash.
    Returns 16-hex-character string.
    """
    if image_or_bytes is None:
        return "0000000000000000"
    if isinstance(image_or_bytes, str) and len(image_or_bytes) == 16 and all(c in "0123456789abcdefABCDEF" for c in image_or_bytes):
        return image_or_bytes.lower()

    try:
        from PIL import Image
        import io
        img = None
        if isinstance(image_or_bytes, str) and os.path.isfile(image_or_bytes):
            img = Image.open(image_or_bytes)
        elif isinstance(image_or_bytes, (bytes, bytearray)):
            img = Image.open(io.BytesIO(image_or_bytes))
        elif hasattr(image_or_bytes, 'resize'):
            img = image_or_bytes

        if img is not None:
            # dHash algorithm: resize to 9x8 grayscale
            resample_filter = getattr(getattr(Image, 'Resampling', Image), 'LANCZOS', getattr(Image, 'ANTIALIAS', 1))
            resized = img.convert("L").resize((9, 8), resample_filter)
            pixels = list(resized.getdata())
            diff = []
            for row in range(8):
                for col in range(8):
                    pixel_left = pixels[row * 9 + col]
                    pixel_right = pixels[row * 9 + col + 1]
                    diff.append(1 if pixel_left > pixel_right else 0)

            val = 0
            for bit in diff:
                val = (val << 1) | bit
            return f"{val:016x}"
    except Exception as e:
        logger.debug("PIL dHash calculation failed (%s); fallback to content hash", e)

    import hashlib
    raw = str(image_or_bytes).encode('utf-8')
    return f"d{hashlib.sha256(raw).hexdigest()[:15]}"


def hamming_distance(hash1: str, hash2: str) -> int:
    """Computes Hamming distance (bit difference) between two 64-bit hex hashes."""
    try:
        val1 = int(str(hash1), 16)
        val2 = int(str(hash2), 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count('1')
    except Exception:
        return sum(c1 != c2 for c1, c2 in zip(str(hash1), str(hash2)))


def record_screen_event(
    proc_name: str,
    window_title: str,
    text_content: Optional[str] = None,
    summary: Optional[str] = None,
    encrypt_at_rest: bool = True,
    image_or_hash: Optional[Any] = None,
    dedup_threshold: int = 4,
    drop_sensitive: bool = False
) -> bool:
    """Records a window event into screen_timeline and indexes in screen_memory_fts.

    Sensitive windows (banking, passwords, incognito) have text redacted to safeguard privacy
    while preserving privacy-hashed perceptual metadata.
    Plaintext is encrypted at rest in screen_timeline, and indexed in FTS5 for instant search.
    """
    is_sens = is_sensitive(window_title, proc_name, text_content or "")
    if is_sens and drop_sensitive:
        logger.debug("Dropping sensitive window per policy: %s (%s)", window_title, proc_name)
        return False

    if is_sens:
        raw_text = "[REDACTED_SENSITIVE_CONTENT]"
        summary = summary or "Sensitive window activity"
    else:
        raw_text = text_content or ""

    stored_text = crypto_vault.encrypt(raw_text) if encrypt_at_rest and raw_text else raw_text
    p_hash = compute_perceptual_hash(image_or_hash or f"{proc_name}:{window_title}")

    with _get_db() as conn:
        cursor = conn.cursor()
        now_ts = time.time()

        # Deduplication check: if latest frame has same process and similar perceptual hash, update timestamp
        if dedup_threshold > 0:
            cursor.execute("SELECT id, perceptual_hash FROM screen_timeline WHERE proc_name = ? ORDER BY timestamp DESC LIMIT 1", (proc_name or "unknown",))
            last_row = cursor.fetchone()
            if last_row and last_row[1]:
                dist = hamming_distance(last_row[1], p_hash)
                if dist <= dedup_threshold:
                    cursor.execute("UPDATE screen_timeline SET timestamp = ? WHERE id = ?", (now_ts, last_row[0]))
                    conn.commit()
                    return True

        cursor.execute("""
            INSERT INTO screen_timeline (timestamp, proc_name, window_title, text_content, summary, perceptual_hash, is_sensitive)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (now_ts, proc_name or "unknown", window_title or "", stored_text, summary or "", p_hash, 1 if is_sens else 0))
        timeline_id = cursor.lastrowid

        # Manual sync to FTS5 virtual table
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO screen_memory_fts (rowid, proc_name, window_title, text_content, summary)
                VALUES (?, ?, ?, ?, ?)
            """, (timeline_id, proc_name or "", window_title or "", raw_text, summary or ""))
        except Exception as fts_err:
            logger.debug("FTS5 sync insert error: %s", fts_err)

        # Store 384-dim embedding in sqlite-vec vec0 virtual table
        if _VEC_AVAILABLE:
            try:
                text_to_embed = " ".join(filter(None, [window_title, raw_text, summary])) or proc_name or ""
                if text_to_embed:
                    vec_bytes = _encode_text_to_vec(text_to_embed)
                    if vec_bytes:
                        cursor.execute("""
                            INSERT OR REPLACE INTO screen_memory_vec (rowid, embedding)
                            VALUES (?, ?)
                        """, (timeline_id, vec_bytes))
            except Exception as vec_err:
                logger.debug("screen_memory_vec insert error: %s", vec_err)

        conn.commit()
    return True


def query_visual_history(
    query: str = "",
    limit: int = 10,
    include_sensitive: bool = False,
    min_ts: Optional[float] = None,
    max_ts: Optional[float] = None
) -> List[Dict[str, Any]]:
    """Natural language and keyword query over visual screen history.
    Retrieves matching timeline frames, decrypts text, and filters out sensitive entries
    unless include_sensitive is True.
    """
    clean_query = (query or "").strip()
    results = []

    with _get_db() as conn:
        cursor = conn.cursor()
        where_clauses = []
        params = []

        if not include_sensitive:
            where_clauses.append("is_sensitive = 0")
        if min_ts is not None:
            where_clauses.append("timestamp >= ?")
            params.append(min_ts)
        if max_ts is not None:
            where_clauses.append("timestamp <= ?")
            params.append(max_ts)

        if clean_query:
            matched_ids = []
            try:
                search_results = search(clean_query, limit=limit * 2)
                matched_ids = [r["id"] for r in search_results if "id" in r]
            except Exception:
                matched_ids = []

            if matched_ids:
                placeholders = ",".join("?" for _ in matched_ids)
                where_clauses.append(f"id IN ({placeholders})")
                params.extend(matched_ids)
            else:
                where_clauses.append("(proc_name LIKE ? OR window_title LIKE ? OR summary LIKE ?)")
                q_wild = f"%{clean_query}%"
                params.extend([q_wild, q_wild, q_wild])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"""
            SELECT id, timestamp, proc_name, window_title, text_content, summary, perceptual_hash, is_sensitive
            FROM screen_timeline
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(sql, params)
        for row in cursor.fetchall():
            r_id, ts, proc, title, enc_text, summary, phash, sens = row
            plain_text = _decrypt_row_text(enc_text) if not sens else "[REDACTED_SENSITIVE_CONTENT]"
            results.append({
                "id": r_id,
                "timestamp": ts,
                "proc_name": proc,
                "window_title": title,
                "text_content": plain_text,
                "summary": summary,
                "perceptual_hash": phash,
                "is_sensitive": bool(sens)
            })

    return results


def store(
    proc_name_or_text: str = "",
    window_title: str = "",
    text_content: Optional[str] = None,
    summary: Optional[str] = None,
    encrypt_at_rest: bool = True,
    **kwargs
) -> bool:
    """Stores a screen memory event with hybrid FTS5 and vector embedding indexing.

    Accepts single text string:
        store("raw text to index")
    or structured parameters:
        store(proc_name, window_title, text_content, summary)
    """
    if not window_title and text_content is None:
        return record_screen_event(
            proc_name="user",
            window_title=proc_name_or_text[:60] if proc_name_or_text else "",
            text_content=proc_name_or_text,
            summary=summary,
            encrypt_at_rest=encrypt_at_rest
        )
    return record_screen_event(
        proc_name=proc_name_or_text,
        window_title=window_title,
        text_content=text_content,
        summary=summary,
        encrypt_at_rest=encrypt_at_rest
    )


def get_recent_timeline(minutes: int = 30, limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves recent timeline entries within the specified timeframe."""
    cutoff = time.time() - (minutes * 60)
    with _get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, proc_name, window_title, text_content, summary
            FROM screen_timeline
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (cutoff, limit))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "timestamp": r[0],
            "proc_name": r[1],
            "window_title": r[2],
            "text_content": _decrypt_row_text(r[3]),
            "summary": r[4],
            "time_str": time.strftime("%H:%M:%S", time.localtime(r[0]))
        })
    return results


def _build_fts5_candidates(query: str) -> List[str]:
    """Generates prioritized FTS5 query variants that avoid syntax errors."""
    q = query.strip()
    candidates = []

    # 1. Quoted exact phrase (escapes embedded double quotes)
    clean_phrase = q.replace('"', '""')
    candidates.append(f'"{clean_phrase}"')

    # 2. Raw query (if simple alphanumeric / no special FTS characters)
    if not any(ch in q for ch in '.*:^()-"\'/\\'):
        candidates.append(q)

    # 3. AND-combined individual terms
    words = [w.strip() for w in q.replace('"', ' ').replace("'", ' ').split() if w.strip()]
    if len(words) > 1:
        token_clause = " AND ".join(f'"{w.replace(chr(34), "")}"' for w in words if w)
        candidates.append(token_clause)

    return candidates


def _search_screen_memory_like(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Fallback search using SQL LIKE and in-memory decryption for encrypted records."""
    if not query:
        return []
    q_lower = query.strip().lower()

    with db_utils.get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, proc_name, window_title, text_content, summary
            FROM screen_timeline
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        rows = cursor.fetchall()

    results = []
    for r in rows:
        decrypted_text = _decrypt_row_text(r[3])
        title = r[2] or ""
        summary = r[4] or ""
        proc = r[1] or ""

        if (q_lower in title.lower() or
            q_lower in decrypted_text.lower() or
            q_lower in summary.lower() or
            q_lower in proc.lower()):
            results.append({
                "timestamp": r[0],
                "proc_name": proc,
                "window_title": title,
                "text_content": decrypted_text,
                "summary": summary,
                "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[0]))
            })
            if len(results) >= limit:
                break
    return results


def _search_fts5_candidates(conn: sqlite3.Connection, query: str, top_k: int = 10) -> List[Tuple[int, float]]:
    """Runs FTS5 BM25 search returning up to top_k (rowid, bm25_rank) tuples."""
    candidates = _build_fts5_candidates(query)
    cursor = conn.cursor()
    for fts_q in candidates:
        try:
            cursor.execute("""
                SELECT f.rowid, f.rank
                FROM screen_memory_fts f
                WHERE screen_memory_fts MATCH ?
                ORDER BY f.rank
                LIMIT ?
            """, (fts_q, top_k))
            rows = cursor.fetchall()
            if rows:
                return [(r[0], float(r[1])) for r in rows]
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as match_err:
            logger.debug("FTS5 candidate '%s' failed: %s", fts_q, match_err)
            continue
    return []


def _search_vector_candidates(conn: sqlite3.Connection, query: str, top_k: int = 10) -> List[Tuple[int, float]]:
    """Runs vector cosine similarity search returning up to top_k (rowid, distance) tuples."""
    global _VEC_AVAILABLE
    if not _VEC_AVAILABLE:
        return []
    try:
        vec_bytes = _encode_text_to_vec(query)
        if not vec_bytes:
            return []
        cursor = conn.cursor()
        cursor.execute("""
            SELECT rowid, distance
            FROM screen_memory_vec
            WHERE embedding MATCH ?
              AND k = ?
            ORDER BY distance
        """, (vec_bytes, top_k))
        rows = cursor.fetchall()
        return [(r[0], float(r[1])) for r in rows]
    except Exception as e:
        logger.debug("Vector search error: %s", e)
        return []


def reciprocal_rank_fusion(
    fts_results: List[Tuple[int, float]],
    vec_results: List[Tuple[int, float]],
    k: int = 60
) -> List[Tuple[int, float, Dict[str, Any]]]:
    """Combines FTS5 BM25 and vector similarity ranks using Reciprocal Rank Fusion (RRF).

    Score formula: RRF(d) = sum(1 / (k + rank_i))
    Returns sorted list of (rowid, rrf_score, rank_meta).
    """
    scores: Dict[int, float] = {}
    meta: Dict[int, Dict[str, Any]] = {}

    for rank, (r_id, bm25_val) in enumerate(fts_results, start=1):
        scores[r_id] = scores.get(r_id, 0.0) + (1.0 / (k + rank))
        meta.setdefault(r_id, {})["bm25_rank"] = rank
        meta[r_id]["bm25_score"] = bm25_val

    for rank, (r_id, dist_val) in enumerate(vec_results, start=1):
        scores[r_id] = scores.get(r_id, 0.0) + (1.0 / (k + rank))
        meta.setdefault(r_id, {})["vector_rank"] = rank
        meta[r_id]["vector_distance"] = dist_val

    sorted_results = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    return [(r_id, score, meta[r_id]) for r_id, score in sorted_results]


def search_screen_memory(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Hybrid BM25 + Vector semantic search engine with Reciprocal Rank Fusion (RRF).

    Runs BOTH SQLite FTS5 BM25 and vector cosine similarity (top-10 each),
    merging and re-ranking candidates using RRF, with graceful fallback to LIKE.

    Args:
        query: Search term or natural language query.
        limit: Maximum number of results to return.

    Returns:
        List of matching screen events with unified relevance ranking.
    """
    if not query or not query.strip():
        return []

    q_clean = query.strip()

    # 1. Attempt hybrid FTS5 BM25 + Vector search with RRF
    try:
        with _get_db() as conn:
            fts_candidates = _search_fts5_candidates(conn, q_clean, top_k=10)
            vec_candidates = _search_vector_candidates(conn, q_clean, top_k=10)

            if fts_candidates or vec_candidates:
                fused = reciprocal_rank_fusion(fts_candidates, vec_candidates, k=60)
                top_fused = fused[:limit]

                row_ids = [r_id for r_id, _, _ in top_fused]
                if row_ids:
                    placeholders = ",".join("?" * len(row_ids))
                    cursor = conn.cursor()
                    cursor.execute(f"""
                        SELECT id, timestamp, proc_name, window_title, text_content, summary
                        FROM screen_timeline
                        WHERE id IN ({placeholders})
                    """, row_ids)
                    row_map = {r[0]: r for r in cursor.fetchall()}

                    results = []
                    for r_id, rrf_score, rank_meta in top_fused:
                        r = row_map.get(r_id)
                        if not r:
                            continue
                        results.append({
                            "id": r[0],
                            "timestamp": r[1],
                            "proc_name": r[2] or "",
                            "window_title": r[3] or "",
                            "text_content": _decrypt_row_text(r[4]),
                            "summary": r[5] or "",
                            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[1])),
                            "rank": rrf_score,
                            "rrf_score": rrf_score,
                            "search_meta": rank_meta
                        })
                    if results:
                        return results

    except Exception as e:
        logger.debug("Hybrid search exception (%s); falling back to LIKE", e)

    # 2. Fallback to LIKE search (also decrypts records in memory)
    return _search_screen_memory_like(q_clean, limit=limit)


def search(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Runs hybrid BM25 + vector semantic search with RRF re-ranking."""
    return search_screen_memory(query, limit=limit)


def search_screen_history(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Searches screen history using hybrid search, returning standardized records."""
    return search_screen_memory(query, limit=limit)


def forget_recent_history(minutes: int = 15) -> int:
    """Immediately purges all recorded screen history from the past N minutes.
    Returns the count of purged events.
    """
    cutoff = time.time() - (minutes * 60)
    with _get_db() as conn:
        cur = conn.cursor()
        # Fetch IDs to purge from both tables (trigger handles FTS, but explicit delete is safer)
        cur.execute("SELECT id FROM screen_timeline WHERE timestamp >= ?", (cutoff,))
        ids = [r[0] for r in cur.fetchall()]

        cur.execute("DELETE FROM screen_timeline WHERE timestamp >= ?", (cutoff,))
        deleted_count = cur.rowcount

        if ids:
            try:
                placeholders = ",".join("?" * len(ids))
                cur.execute(f"DELETE FROM screen_memory_fts WHERE rowid IN ({placeholders})", ids)
            except Exception:
                pass

            if _VEC_AVAILABLE:
                try:
                    for r_id in ids:
                        cur.execute("DELETE FROM screen_memory_vec WHERE rowid = ?", (r_id,))
                except Exception as vec_del_err:
                    logger.debug("screen_memory_vec delete error: %s", vec_del_err)

        conn.commit()

    logger.info("Purged %d screen history records from the last %d minutes.", deleted_count, minutes)
    return deleted_count


def cleanup_expired_retention(retention_hours: int = 24) -> int:
    """Removes historical screen timeline records older than the retention TTL."""
    cutoff = time.time() - (retention_hours * 3600)
    with _get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM screen_timeline WHERE timestamp < ?", (cutoff,))
        ids = [r[0] for r in cur.fetchall()]

        cur.execute("DELETE FROM screen_timeline WHERE timestamp < ?", (cutoff,))
        purged = cur.rowcount

        if ids:
            try:
                placeholders = ",".join("?" * len(ids))
                cur.execute(f"DELETE FROM screen_memory_fts WHERE rowid IN ({placeholders})", ids)
            except Exception:
                pass

            if _VEC_AVAILABLE:
                try:
                    for r_id in ids:
                        cur.execute("DELETE FROM screen_memory_vec WHERE rowid = ?", (r_id,))
                except Exception as vec_del_err:
                    logger.debug("screen_memory_vec delete error: %s", vec_del_err)

        conn.commit()

    logger.info("Pruned %d expired screen timeline entries older than %d hours.", purged, retention_hours)
    return purged


def summarize_timeline_text(minutes: int = 30) -> str:
    """Summarizes recent window activity into a concise bullet list."""
    events = get_recent_timeline(minutes=minutes, limit=15)
    if not events:
        return f"🖥️ Screen Timeline: No active window history recorded in the last {minutes} minutes."

    lines = [f"🖥️ Screen Timeline (Last {minutes} min):"]
    seen = set()
    for ev in events:
        key = f"{ev['proc_name']}:{ev['window_title']}"
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"• [{ev['time_str']}] {ev['proc_name']} — {ev['window_title']}")
    return "\n".join(lines)


def capture_and_record_active_window(force_ocr: bool = True) -> Tuple[bool, str]:
    """Explicitly triggers OCR capture and indexing for the current foreground window.

    Extracts text from modern windows (browsers, IDEs, documents) and stores it.
    """
    try:
        fw = windows_tools.get_foreground_window()
        if not fw:
            return False, "No active foreground window found."

        title = fw.get("title", "")
        proc = fw.get("proc_name", "")
        hwnd = fw.get("hwnd", 0)

        if is_sensitive(title, proc):
            return False, f"Window '{title}' ({proc}) is excluded by privacy policy."

        # 1. Win32 window text
        text_sample = ""
        try:
            text_sample = windows_tools.read_window_text(hwnd)
        except Exception:
            pass

        # 2. Hardware OCR extraction
        ocr_text = ""
        if force_ocr and screen_ocr_engine:
            try:
                ocr_text = screen_ocr_engine.capture_and_extract_text(hwnd=hwnd) or ""
            except Exception as e:
                logger.debug("Triggered OCR capture error: %s", e)

        # Merge extracted text
        parts = []
        if text_sample and text_sample.strip():
            parts.append(text_sample.strip())
        if ocr_text and ocr_text.strip() and ocr_text.strip() not in text_sample:
            parts.append(ocr_text.strip())
        combined_text = "\n".join(parts)

        ok = record_screen_event(proc, title, text_content=combined_text[:3000] if combined_text else "")
        if ok:
            return True, f"Indexed active window '{title}' ({len(combined_text)} characters captured)."
        return False, "Failed to record window event."
    except Exception as e:
        logger.error("capture_and_record_active_window failed: %s", e)
        return False, str(e)


def _monitor_loop(poll_interval: int = 15):
    """Background polling loop that samples the active foreground window and runs OCR."""
    global _monitor_running
    last_title = ""
    last_proc = ""

    while _monitor_running:
        try:
            fw = windows_tools.get_foreground_window()
            if fw:
                title = fw.get("title", "")
                proc = fw.get("proc_name", "")
                hwnd = fw.get("hwnd", 0)

                if title and (title != last_title or proc != last_proc):
                    last_title = title
                    last_proc = proc

                    # Check privacy exclusion before OCR capture
                    if is_sensitive(title, proc):
                        logger.debug("Skipping sensitive window in monitor loop: %s (%s)", title, proc)
                        time.sleep(poll_interval)
                        continue

                    # 1. Window text via Win32
                    text_sample = ""
                    try:
                        text_sample = windows_tools.read_window_text(hwnd)
                    except Exception:
                        pass

                    # 2. Hardware OCR extraction for modern apps (browsers, editors)
                    ocr_text = ""
                    if screen_ocr_engine:
                        try:
                            ocr_text = screen_ocr_engine.capture_and_extract_text(hwnd=hwnd) or ""
                        except Exception as ocr_err:
                            logger.debug("Monitor OCR capture failed: %s", ocr_err)

                    # Merge Win32 and OCR text
                    parts = []
                    if text_sample and text_sample.strip():
                        parts.append(text_sample.strip())
                    if ocr_text and ocr_text.strip() and ocr_text.strip() not in text_sample:
                        parts.append(ocr_text.strip())
                    combined_text = "\n".join(parts)

                    record_screen_event(proc, title, text_content=combined_text[:3000] if combined_text else "")
        except Exception as e:
            logger.debug("Screen monitor error: %s", e)
        time.sleep(poll_interval)


def start_screen_monitor(poll_interval: int = 15) -> Tuple[bool, str]:
    """Starts the background screen memory monitoring thread."""
    global _monitor_running, _monitor_thread
    if _monitor_running:
        return True, "Screen memory monitor is already running."

    _monitor_running = True
    _monitor_thread = threading.Thread(target=_monitor_loop, args=(poll_interval,), daemon=True)
    _monitor_thread.start()
    return True, "Screen memory monitor started."


def stop_screen_monitor() -> Tuple[bool, str]:
    """Stops the background screen memory monitoring thread."""
    global _monitor_running
    _monitor_running = False
    return True, "Screen memory monitor stopped."
