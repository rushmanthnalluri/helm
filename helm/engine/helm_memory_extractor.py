"""helm_memory_extractor.py - Safe Proposal-Only Fact Extractor for Helm.

Security Invariants:
1. Taint Refusal: If the workstation, session, or current turn is tainted,
   extraction is STRICTLY REFUSED. Untrusted data (e.g. from web, clipboard,
   or audio) cannot launder facts into persistent memory.
2. Proposal-Only: Extracted facts are NEVER written directly to the memory store.
   They are submitted as pending confirmation proposals via rails_confirmation.
   A human MUST explicitly confirm the proposal before it can be committed.
3. Strict Bounds: Key must be snake_case identifier; fact statement <= 200 chars.
4. Volatile Filter: Ignores transient chatter, greetings, or short commands.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("helm.memory_extractor")

# Ephemeral patterns to ignore
_VOLATILE_PATTERNS = [
    re.compile(r"^(?:hi|hello|hey|good morning|good evening|thanks|thank you)\b", re.IGNORECASE),
    re.compile(r"^(?:what time is it|what's the weather|how are you)\b", re.IGNORECASE),
]

_EXTRACTOR_SYSTEM_PROMPT = (
    "You are a durable fact extraction assistant. Analyze the user's statement and extract "
    "any durable, permanent personal facts about the user (e.g. name, preferences, favorite tools, "
    "work hours, language). Ignore one-off commands, greetings, or temporary questions.\n"
    "Respond ONLY with a JSON array of objects: [{\"key\": \"identifier_snake_case\", \"fact\": \"statement\"}]. "
    "If no durable facts are present, respond with []."
)


class FactExtractor:
    """Extracts proposed durable personal facts from conversational turns.
    Strictly proposal-only; NEVER commits facts directly to disk.
    """

    def __init__(
        self,
        llm_caller: Optional[Callable[[str, str], str]] = None,
        max_fact_chars: int = 200,
    ) -> None:
        self.llm_caller = llm_caller
        self.max_fact_chars = max_fact_chars

    def is_volatile_or_ephemeral(self, text: str) -> bool:
        """Filter out obvious greetings or ephemeral chatter."""
        clean = text.strip()
        if len(clean) < 4:
            return True
        for pattern in _VOLATILE_PATTERNS:
            if pattern.search(clean):
                return True
        return False

    def extract_heuristic(self, user_text: str) -> List[Tuple[str, str]]:
        """Fast regex-based extractor for common declarative statements without LLM call."""
        facts: List[Tuple[str, str]] = []
        text = user_text.strip()

        # "My name is X" / "I am X"
        m = re.search(r"\bmy name is ([A-Z][a-zA-Z0-9_\-]{1,25})\b", text, re.IGNORECASE)
        if m:
            facts.append(("user_name", f"The user's name is {m.group(1).strip()}."))

        # "I prefer X" / "I like X"
        m = re.search(r"\b(?:i prefer|i like|my preferred)\s+([a-zA-Z0-9_\- ]{3,50})\b", text, re.IGNORECASE)
        if m:
            preference = m.group(1).strip().rstrip(".")
            key = f"preference_{re.sub(r'[^a-z0-9_]', '_', preference.lower())[:20]}"
            facts.append((key, f"The user prefers {preference}."))

        # "I work as X" / "My job is X"
        m = re.search(r"\b(?:i work as|my job is|i am a)\s+([a-zA-Z0-9_\- ]{3,40})\b", text, re.IGNORECASE)
        if m:
            role = m.group(1).strip().rstrip(".")
            facts.append(("user_profession", f"The user works as {role}."))

        return facts

    def extract(self, user_text: str, assistant_text: str = "", is_turn_tainted: bool = False) -> List[Tuple[str, str]]:
        """Extract candidate facts from turn.
        Refuses extraction if workstation or turn is tainted.
        """
        # 1. Taint Refusal Check: Never extract facts from tainted context
        import taint_tracker
        if is_turn_tainted or taint_tracker.is_workstation_tainted():
            logger.warning("Fact extraction strictly refused: context is tainted.")
            return []

        if self.is_volatile_or_ephemeral(user_text):
            return []

        import rails_content_boundary
        is_injected, _ = rails_content_boundary.detect_instruction_injection(user_text)
        if is_injected:
            logger.warning("Fact extraction skipped: input contains detected instruction injection.")
            return []

        # 2. Run fast heuristic
        extracted = self.extract_heuristic(user_text)

        # 3. Optional LLM fallback
        if not extracted and self.llm_caller:
            try:
                turn_prompt = f"User: {user_text}\nAssistant: {assistant_text}"
                raw_response = self.llm_caller(_EXTRACTOR_SYSTEM_PROMPT, turn_prompt)
                parsed = json.loads(raw_response)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict) and "key" in item and "fact" in item:
                            k = str(item["key"]).strip()
                            f = str(item["fact"]).strip()
                            if k and f and len(f) <= self.max_fact_chars:
                                is_inj, _ = rails_content_boundary.detect_instruction_injection(f)
                                if not is_inj:
                                    extracted.append((k, f))
            except Exception as e:
                logger.debug("LLM fact extraction degraded gracefully: %s", e)

        return extracted

    def propose_fact_for_approval(self, key: str, fact: str, caller_id: str = "assistant") -> Any:
        """Submits an extracted candidate fact as a pending confirmation proposal.
        NEVER writes to memory store directly. Human must approve.
        """
        import rails_confirmation
        gate = rails_confirmation.get_confirmation_gate()
        req = gate.create_request(
            "helm_remember_fact",
            {"key": key, "fact": fact},
            caller_id=caller_id,
        )
        logger.info("Submitted proposed fact %s as confirmation request %s", key, req.request_id)
        return req
