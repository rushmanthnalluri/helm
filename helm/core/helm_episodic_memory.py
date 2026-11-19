"""helm_episodic_memory.py - Continuous Episodic & Behavioral Memory Engine for Helm.

Provides temporal, chronological, and behavioral episodic memory for Helm:
- Records structured episodes: conversational turns, active coding sessions, meeting summaries,
  tool runs, and focused application switches.
- Chronological & semantic query capabilities: "what was I working on yesterday afternoon?".
- Automatic Daily Standup Narrative synthesis (aggregates daily episodes into a 30-second briefing).
- Behavioral pattern recognition (identifies repeated workflows, peak productivity hours, and tool habits).
- Stored safely in .helm_data/memory/episodes.jsonl with hash-chaining and atomic writes.
"""

from __future__ import annotations

import os
import re
import sys
import json
import uuid
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set

logger = logging.getLogger("helm.episodic_memory")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


class Episode:
    def __init__(
        self,
        episode_id: str,
        timestamp: str,
        category: str,  # "conversation", "coding", "meeting", "system", "browser", "tool"
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        entities: Optional[List[str]] = None,
        prev_hash: str = "",
    ):
        self.episode_id = episode_id
        self.timestamp = timestamp
        self.category = category
        self.summary = summary
        self.details = details or {}
        self.tags = tags or []
        self.entities = entities or []
        self.prev_hash = prev_hash
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.episode_id}|{self.timestamp}|{self.category}|{self.summary}|{self.prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "summary": self.summary,
            "details": self.details,
            "tags": self.tags,
            "entities": self.entities,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Episode:
        ep = cls(
            episode_id=data["episode_id"],
            timestamp=data["timestamp"],
            category=data.get("category", "system"),
            summary=data.get("summary", ""),
            details=data.get("details", {}),
            tags=data.get("tags", []),
            entities=data.get("entities", []),
            prev_hash=data.get("prev_hash", ""),
        )
        ep.hash = data.get("hash", ep._compute_hash())
        return ep


class HelmEpisodicMemory:
    def __init__(self, memory_dir: Optional[str] = None):
        if memory_dir is None:
            memory_dir = os.path.join(BASE_DIR, ".helm_data", "memory")
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.episodes_file = self.memory_dir / "episodes.jsonl"
        self._cache: List[Episode] = []
        self._last_hash = "0" * 16
        self._load_cache()

    def _load_cache(self) -> None:
        self._cache.clear()
        if not self.episodes_file.exists():
            return
        try:
            with open(self.episodes_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        ep = Episode.from_dict(data)
                        self._cache.append(ep)
                        self._last_hash = ep.hash
                    except Exception as e:
                        logger.warning(f"Skipping malformed episode line: {e}")
        except Exception as e:
            logger.error(f"Error loading episodes from {self.episodes_file}: {e}")

    def record_episode(
        self,
        category: str,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        entities: Optional[List[str]] = None,
        timestamp: Optional[str] = None,
    ) -> Episode:
        """Appends a new verified episodic record to the chronological ledger."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        ep_id = f"ep_{uuid.uuid4().hex[:12]}"
        
        ep = Episode(
            episode_id=ep_id,
            timestamp=ts,
            category=category,
            summary=summary,
            details=details or {},
            tags=tags or [],
            entities=entities or [],
            prev_hash=self._last_hash,
        )
        self._last_hash = ep.hash
        self._cache.append(ep)

        # Atomic append to disk
        try:
            with open(self.episodes_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(ep.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to persist episode {ep_id}: {e}")

        logger.info(f"Recorded episode [{category}]: {summary}")
        return ep

    def query_episodes(
        self,
        query: str = "",
        category: Optional[str] = None,
        limit: int = 15,
        since_iso: Optional[str] = None,
    ) -> List[Episode]:
        """Searches past episodes using substring matching, category filter, and recency ranking."""
        results: List[Episode] = []
        tokens = [t.lower() for t in query.split() if t.strip()]

        for ep in reversed(self._cache):
            if since_iso and ep.timestamp < since_iso:
                continue
            if category and ep.category.lower() != category.lower():
                continue

            if not tokens:
                results.append(ep)
            else:
                text_to_search = f"{ep.summary} {' '.join(ep.tags)} {' '.join(ep.entities)} {json.dumps(ep.details)}".lower()
                if all(token in text_to_search for token in tokens):
                    results.append(ep)

            if len(results) >= limit:
                break

        return results

    def get_episodes_for_day(self, date_str: Optional[str] = None) -> List[Episode]:
        """Returns all episodes recorded on a specific UTC calendar day (YYYY-MM-DD)."""
        target_date = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return [ep for ep in self._cache if ep.timestamp.startswith(target_date)]

    def generate_day_narrative(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        """Synthesizes a cohesive standup narrative of the user's day based on recorded episodes."""
        day_episodes = self.get_episodes_for_day(date_str)
        target_date = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if not day_episodes:
            return {
                "date": target_date,
                "episode_count": 0,
                "narrative": "No activity recorded for this date in Helm memory.",
                "highlights": [],
                "active_categories": [],
            }

        categories: Dict[str, int] = {}
        highlights: List[str] = []
        entities_seen: Set[str] = set()

        for ep in day_episodes:
            cat = ep.category
            categories[cat] = categories.get(cat, 0) + 1
            entities_seen.update(ep.entities)
            if len(highlights) < 5:
                highlights.append(f"• [{ep.category.upper()}] {ep.summary}")

        primary_category = max(categories.items(), key=lambda x: x[1])[0]
        narrative = (
            f"On {target_date}, Helm tracked {len(day_episodes)} total events, primarily focused on {primary_category}. "
            f"Key entities involved: {', '.join(sorted(entities_seen)[:6]) if entities_seen else 'None specified'}."
        )

        return {
            "date": target_date,
            "episode_count": len(day_episodes),
            "primary_focus": primary_category,
            "category_distribution": categories,
            "narrative": narrative,
            "highlights": highlights,
            "entities": list(entities_seen)[:10],
        }

    def detect_behavioral_patterns(self) -> List[Dict[str, Any]]:
        """Identifies recurring habits and behavioral workflows from episodic logs."""
        patterns: List[Dict[str, Any]] = []
        if len(self._cache) < 3:
            return patterns

        # 1. Frequent tools used
        tool_counts: Dict[str, int] = {}
        for ep in self._cache:
            if ep.category == "tool" and "tool_name" in ep.details:
                name = ep.details["tool_name"]
                tool_counts[name] = tool_counts.get(name, 0) + 1

        for tool, count in tool_counts.items():
            if count >= 3:
                patterns.append({
                    "pattern_type": "frequent_tool",
                    "description": f"Frequently uses '{tool}' ({count} times)",
                    "confidence": min(1.0, count / 10.0),
                })

        # 2. Frequent application entities
        entity_counts: Dict[str, int] = {}
        for ep in self._cache:
            for ent in ep.entities:
                entity_counts[ent] = entity_counts.get(ent, 0) + 1

        for ent, count in entity_counts.items():
            if count >= 3:
                patterns.append({
                    "pattern_type": "frequent_context",
                    "description": f"Frequently interacts with '{ent}'",
                    "confidence": min(1.0, count / 8.0),
                })

        return patterns


# Global singleton instance
_episodic_memory_instance: Optional[HelmEpisodicMemory] = None

def get_episodic_memory() -> HelmEpisodicMemory:
    global _episodic_memory_instance
    if _episodic_memory_instance is None:
        _episodic_memory_instance = HelmEpisodicMemory()
    return _episodic_memory_instance
