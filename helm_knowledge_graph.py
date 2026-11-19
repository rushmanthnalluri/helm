"""helm_knowledge_graph.py - Temporal Personal Knowledge Graph for Helm.

Connects People, Projects, Meetings, Files, Dates, Topics, and Organizations
with directional relations, confidence scoring, temporal timestamps, and provenance tracking.
Enables instant dossier lookup:
e.g. "Who is Alice?" -> Works on Project Delta, attended 3 meetings, 2 action items assigned.

Features:
- Entity Store: Normalized names, aliases, category classification, rich metadata.
- Temporal Edge Store: (Subject -[Predicate]-> Object) with timestamp, context, confidence, provenance.
- Entity Dossier Synthesis: Compiles 360-degree dossiers including direct relations, 2-hop connections,
  recent interactions, and open action items.
- Injection Defense: Filters untrusted injection payloads from entering graph entities/relations.
- SQLite WAL Persistence: Zero lock contention, thread-safe, fast graph queries.
"""

from __future__ import annotations

import os
import re
import json
import time
import sqlite3
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GRAPH_DB_PATH = os.path.join(BASE_DIR, "data", "helm_knowledge_graph.db")
os.makedirs(os.path.dirname(GRAPH_DB_PATH), exist_ok=True)

# Prompt injection detector to prevent poisoned data in graph
_INJECTION_PATTERN = re.compile(
    r"\b(?:ignore|disregard|override)\s+(?:all|any|previous|prior|system)\b|"
    r"\bsystem\s+prompt\b|"
    r"\b(?:you|the\s+assistant|helm)\s+(?:must|shall|have\s+to|will)\b|"
    r"javascript:|data:text/html",
    re.I
)

# Valid entity categories
VALID_CATEGORIES = {
    "person", "project", "meeting", "file", "date", "topic",
    "tool", "organization", "place", "task", "misc"
}

# Standard predicate relations
STANDARD_PREDICATES = {
    "works_on", "assigned_to", "attended", "leads", "created",
    "authored", "depends_on", "relates_to", "mentioned_in",
    "decided_in", "part_of", "manages", "reported_by", "scheduled_for"
}


def _get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or GRAPH_DB_PATH
    conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
    except Exception:
        pass
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL COLLATE NOCASE,
            category TEXT NOT NULL,
            aliases TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
    """)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_entities_name ON entities(name);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_category ON entities(category);")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS relations (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            source_name TEXT NOT NULL COLLATE NOCASE,
            predicate TEXT NOT NULL COLLATE NOCASE,
            target_id TEXT NOT NULL,
            target_name TEXT NOT NULL COLLATE NOCASE,
            context TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 1.0,
            provenance TEXT NOT NULL DEFAULT '',
            timestamp REAL NOT NULL,
            FOREIGN KEY (source_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES entities(id) ON DELETE CASCADE
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relations(source_name);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relations(target_name);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_pred ON relations(predicate);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_time ON relations(timestamp);")
    conn.commit()


def _sanitize_text(text: str, max_chars: int = 400) -> str:
    cleaned = text.strip()[:max_chars]
    if _INJECTION_PATTERN.search(cleaned):
        raise ValueError(f"Content failed safety validation: potential prompt injection detected.")
    return cleaned


def _entity_id(name: str) -> str:
    return hashlib.sha256(name.strip().lower().encode("utf-8")).hexdigest()[:16]


def _relation_id(source_name: str, predicate: str, target_name: str, timestamp: float) -> str:
    key = f"{source_name.strip().lower()}|{predicate.strip().lower()}|{target_name.strip().lower()}|{int(timestamp)}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def add_or_update_entity(
    name: str,
    category: str = "misc",
    aliases: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Adds or updates an entity in the personal knowledge graph."""
    clean_name = _sanitize_text(name, max_chars=120)
    if not clean_name:
        raise ValueError("Entity name cannot be empty.")
    
    cat = category.lower().strip()
    if cat not in VALID_CATEGORIES:
        cat = "misc"

    ent_id = _entity_id(clean_name)
    now = time.time()
    aliases_json = json.dumps(aliases or [])
    metadata_json = json.dumps(metadata or {})

    conn = _get_connection(db_path)
    try:
        with conn:
            existing = conn.execute("SELECT id, aliases, metadata FROM entities WHERE id = ?", (ent_id,)).fetchone()
            if existing:
                # Merge aliases and metadata
                old_aliases = set(json.loads(existing["aliases"]))
                if aliases:
                    old_aliases.update([_sanitize_text(a, 60) for a in aliases if a.strip()])
                
                old_meta = json.loads(existing["metadata"])
                if metadata:
                    old_meta.update(metadata)

                conn.execute("""
                    UPDATE entities
                    SET category = ?, aliases = ?, metadata = ?, updated_at = ?
                    WHERE id = ?
                """, (cat, json.dumps(list(old_aliases)), json.dumps(old_meta), now, ent_id))
            else:
                conn.execute("""
                    INSERT INTO entities (id, name, category, aliases, metadata, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (ent_id, clean_name, cat, aliases_json, metadata_json, now, now))
        return {
            "id": ent_id,
            "name": clean_name,
            "category": cat,
            "updated_at": now
        }
    finally:
        conn.close()


def link_entities(
    source_name: str,
    predicate: str,
    target_name: str,
    source_category: str = "misc",
    target_category: str = "misc",
    context: str = "",
    confidence: float = 1.0,
    provenance: str = "manual",
    timestamp: Optional[float] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Creates a directed relationship between two entities.
    Automatically creates the entities if they do not yet exist.
    """
    clean_src = _sanitize_text(source_name, max_chars=120)
    clean_tgt = _sanitize_text(target_name, max_chars=120)
    clean_pred = _sanitize_text(predicate, max_chars=60).lower().replace(" ", "_")
    clean_ctx = _sanitize_text(context, max_chars=500) if context else ""
    ts = float(timestamp) if timestamp is not None else time.time()
    conf = max(0.0, min(1.0, float(confidence)))

    if not clean_src or not clean_tgt or not clean_pred:
        raise ValueError("Source, predicate, and target must be non-empty.")

    # Ensure both entities exist
    add_or_update_entity(clean_src, category=source_category, db_path=db_path)
    add_or_update_entity(clean_tgt, category=target_category, db_path=db_path)

    src_id = _entity_id(clean_src)
    tgt_id = _entity_id(clean_tgt)
    rel_id = _relation_id(clean_src, clean_pred, clean_tgt, ts)

    conn = _get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO relations
                (id, source_id, source_name, predicate, target_id, target_name, context, confidence, provenance, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (rel_id, src_id, clean_src, clean_pred, tgt_id, clean_tgt, clean_ctx, conf, provenance, ts))
        return {
            "id": rel_id,
            "source": clean_src,
            "predicate": clean_pred,
            "target": clean_tgt,
            "context": clean_ctx,
            "confidence": conf,
            "timestamp": ts
        }
    finally:
        conn.close()


def get_entity_dossier(entity_name: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Retrieves a comprehensive 360-degree knowledge dossier for a named entity:
    - Profile info, category, aliases
    - Outgoing relationships (What does this entity do/relate to?)
    - Incoming relationships (Who relates to this entity?)
    - 2-hop connected entities (Colleagues on the same projects, related topics)
    - Action items and decisions
    """
    clean_name = entity_name.strip()
    conn = _get_connection(db_path)
    try:
        # Find exact or alias match
        row = conn.execute("""
            SELECT * FROM entities 
            WHERE name = ? COLLATE NOCASE OR aliases LIKE ?
            LIMIT 1
        """, (clean_name, f'%"{clean_name}"%')).fetchone()

        if not row:
            # Check if there are relations mentioning it anyway
            rel_check = conn.execute("""
                SELECT source_name FROM relations WHERE source_name = ? COLLATE NOCASE
                UNION
                SELECT target_name FROM relations WHERE target_name = ? COLLATE NOCASE
                LIMIT 1
            """, (clean_name, clean_name)).fetchone()
            if not rel_check:
                return {
                    "ok": False,
                    "error": f"Entity '{clean_name}' not found in knowledge graph.",
                    "found": False
                }
            canonical_name = clean_name
            category = "misc"
            aliases = []
            metadata = {}
            created_at = time.time()
            updated_at = created_at
        else:
            canonical_name = row["name"]
            category = row["category"]
            aliases = json.loads(row["aliases"])
            metadata = json.loads(row["metadata"])
            created_at = row["created_at"]
            updated_at = row["updated_at"]

        # Outgoing relations
        out_rows = conn.execute("""
            SELECT predicate, target_name, context, confidence, provenance, timestamp
            FROM relations
            WHERE source_name = ? COLLATE NOCASE
            ORDER BY timestamp DESC
        """, (canonical_name,)).fetchall()

        outgoing = []
        target_names = set()
        for r in out_rows:
            outgoing.append({
                "predicate": r["predicate"],
                "target": r["target_name"],
                "context": r["context"],
                "confidence": r["confidence"],
                "provenance": r["provenance"],
                "timestamp": r["timestamp"]
            })
            target_names.add(r["target_name"].lower())

        # Incoming relations
        in_rows = conn.execute("""
            SELECT source_name, predicate, context, confidence, provenance, timestamp
            FROM relations
            WHERE target_name = ? COLLATE NOCASE
            ORDER BY timestamp DESC
        """, (canonical_name,)).fetchall()

        incoming = []
        source_names = set()
        for r in in_rows:
            incoming.append({
                "source": r["source_name"],
                "predicate": r["predicate"],
                "context": r["context"],
                "confidence": r["confidence"],
                "provenance": r["provenance"],
                "timestamp": r["timestamp"]
            })
            source_names.add(r["source_name"].lower())

        # 2nd-degree connections (e.g. people linked to the same projects/topics)
        connected_2hop = []
        if outgoing:
            shared_targets = [r["target"] for r in outgoing if r["predicate"] in ("works_on", "part_of", "attended")]
            if shared_targets:
                placeholders = ",".join(["?"] * len(shared_targets))
                two_hop_rows = conn.execute(f"""
                    SELECT DISTINCT source_name, predicate, target_name
                    FROM relations
                    WHERE target_name IN ({placeholders})
                      AND source_name != ? COLLATE NOCASE
                    LIMIT 15
                """, (*shared_targets, canonical_name)).fetchall()
                for th in two_hop_rows:
                    connected_2hop.append({
                        "entity": th["source_name"],
                        "shared_via": th["target_name"],
                        "relation": th["predicate"]
                    })

        # Summary of active action items or decisions
        action_items = [
            r for r in outgoing if r["predicate"] in ("assigned_to", "task", "action_item", "deliverable")
        ] + [
            r for r in incoming if r["predicate"] in ("assigned_to", "action_item")
        ]

        return {
            "ok": True,
            "found": True,
            "entity": canonical_name,
            "category": category,
            "aliases": aliases,
            "metadata": metadata,
            "first_seen": created_at,
            "last_updated": updated_at,
            "relationships_out": outgoing,
            "relationships_in": incoming,
            "second_degree_connections": connected_2hop,
            "action_items": action_items,
            "summary_text": _format_dossier_summary(canonical_name, category, outgoing, incoming, connected_2hop, action_items)
        }
    finally:
        conn.close()


def _format_dossier_summary(
    name: str,
    category: str,
    outgoing: List[Dict[str, Any]],
    incoming: List[Dict[str, Any]],
    two_hop: List[Dict[str, Any]],
    action_items: List[Dict[str, Any]]
) -> str:
    """Formats a concise human-readable brief for the dossier."""
    lines = [f"**Dossier: {name}** ({category.title()})"]
    if outgoing:
        lines.append("\n*Direct Connections:*")
        for r in outgoing[:8]:
            ctx = f" — {r['context']}" if r['context'] else ""
            lines.append(f"- {name} {r['predicate'].replace('_', ' ')} **{r['target']}**{ctx}")
    if incoming:
        lines.append("\n*Referenced By:*")
        for r in incoming[:8]:
            ctx = f" — {r['context']}" if r['context'] else ""
            lines.append(f"- **{r['source']}** {r['predicate'].replace('_', ' ')} {name}{ctx}")
    if action_items:
        lines.append("\n*Action Items / Tasks:*")
        for a in action_items[:5]:
            tgt = a.get("target") or a.get("source")
            lines.append(f"- [ ] {tgt}: {a.get('context', 'Open task')}")
    if two_hop:
        lines.append("\n*Related Network:*")
        for th in two_hop[:5]:
            lines.append(f"- Also connected with **{th['entity']}** via {th['shared_via']}")
    return "\n".join(lines)


def search_knowledge_graph(
    query: str,
    category: Optional[str] = None,
    limit: int = 15,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Searches entities and relations across the graph."""
    q = query.strip()
    if not q:
        return []
    
    conn = _get_connection(db_path)
    try:
        sql = """
            SELECT id, name, category, aliases, metadata, updated_at
            FROM entities
            WHERE (name LIKE ? OR aliases LIKE ? OR metadata LIKE ?)
        """
        params = [f"%{q}%", f"%{q}%", f"%{q}%"]
        if category and category.lower() in VALID_CATEGORIES:
            sql += " AND category = ?"
            params.append(category.lower())
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(limit))

        rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "name": r["name"],
                "category": r["category"],
                "aliases": json.loads(r["aliases"]),
                "metadata": json.loads(r["metadata"]),
                "updated_at": r["updated_at"]
            })
        return results
    finally:
        conn.close()


def extract_and_link(
    text: str,
    provenance: str = "context_extractor",
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Heuristic extractor that automatically discovers and links entities from natural sentences.
    e.g. "Alice is working on Project Delta" -> (Alice -[works_on]-> Project Delta)
         "Meeting with Bob regarding Q3 Roadmap" -> (Bob -[relates_to]-> Q3 Roadmap)
    """
    if _INJECTION_PATTERN.search(text):
        return []

    created_links = []
    # Pattern 1: X is working on Y
    p1 = re.findall(r"([A-Z][a-zA-Z0-9_\s]{1,30})\s+(?:is\s+working\s+on|works\s+on|contributing\s+to)\s+([A-Z][a-zA-Z0-9_\s]{1,40})", text)
    for src, tgt in p1:
        src_clean = src.strip()
        tgt_clean = tgt.strip()
        if src_clean and tgt_clean and src_clean.lower() != tgt_clean.lower():
            link = link_entities(
                source_name=src_clean,
                predicate="works_on",
                target_name=tgt_clean,
                source_category="person",
                target_category="project",
                context=text[:200],
                provenance=provenance,
                db_path=db_path
            )
            created_links.append(link)

    # Pattern 2: Meeting with X about/regarding Y
    p2 = re.findall(r"(?:Meeting|Sync|Call|Chat)\s+(?:with\s+)?([A-Z][a-zA-Z0-9_\s]{1,30})\s+(?:about|on|regarding)\s+([A-Z][a-zA-Z0-9_\s]{1,40})", text, re.I)
    for src, tgt in p2:
        src_clean = src.strip()
        tgt_clean = tgt.strip()
        if src_clean and tgt_clean:
            link = link_entities(
                source_name=src_clean,
                predicate="relates_to",
                target_name=tgt_clean,
                source_category="person",
                target_category="topic",
                context=text[:200],
                provenance=provenance,
                db_path=db_path
            )
            created_links.append(link)

    # Pattern 3: X assigned to Y or Y assigned to X
    p3 = re.findall(r"(?:assigned|assigning)\s+(?:task\s+)?([A-Z][a-zA-Z0-9_\s]{1,40})\s+to\s+([A-Z][a-zA-Z0-9_\s]{1,30})", text, re.I)
    for task_name, person_name in p3:
        task_clean = task_name.strip()
        person_clean = person_name.strip()
        if task_clean and person_clean:
            link = link_entities(
                source_name=person_clean,
                predicate="assigned_to",
                target_name=task_clean,
                source_category="person",
                target_category="task",
                context=text[:200],
                provenance=provenance,
                db_path=db_path
            )
            created_links.append(link)

    return created_links
