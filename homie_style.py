"""homie_style.py - Output Styling & Anti-Slop Deterministic Post-Processor.

Applies a 0-token deterministic pass over generated replies, emails, and notes:
- Cleans em-dashes and en-dashes into clean hyphens or commas.
- Strips AI sycophancy & corporate slop phrases ("Certainly!", "Great question!",
  "In today's fast-paced world", "delve", "rich tapestry", "game-changer", "as an AI").
- Preserves code blocks, inline backticks, URLs, file paths, and mathematical notation.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# AI fluff phrases and replacements
SLOP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcertainly[!.]?\s*", re.I), ""),
    (re.compile(r"\babsolutely[!.]?\s*", re.I), ""),
    (re.compile(r"\bgreat\s+question[!.]?\s*", re.I), ""),
    (re.compile(r"\bexcellent\s+question[!.]?\s*", re.I), ""),
    (re.compile(r"i\s+hope\s+(?:this|my)\s+(?:e-?mail|message|note)\s+finds\s+you\s+well[,.!]?\s*", re.I), ""),
    (re.compile(r"in\s+today'?s\s+(?:fast-paced|digital|modern|ever-changing)\s+(?:world|age|era|landscape)[,.]?\s*", re.I), ""),
    (re.compile(r"as\s+an\s+ai(?:\s+language\s+model)?,\s*", re.I), ""),
    (re.compile(r"i(?:'d|\s+would)\s+be\s+(?:happy|delighted|thrilled)\s+to\s+help\b[,.]?\s*", re.I), ""),
    (re.compile(r"\bdelv(?:e|es|ing)\s+into\b", re.I), "explore"),
    (re.compile(r"\bdelve\b", re.I), "look"),
    (re.compile(r"\b(?:a\s+)?rich\s+tapestry\s+of\b", re.I), "a mix of"),
    (re.compile(r"\btapestry\b", re.I), "mix"),
    (re.compile(r"\bgame[- ]changers?\b", re.I), "big shift"),
    (re.compile(r"\bleverag(?:e|ing)\s+synerg(?:y|ies)\b", re.I), "collaborating"),
    (re.compile(r"\bleverag(?:e|es|ed|ing)\b", re.I), "use"),
]

# Protected spans: fenced code, inline code, URLs, paths
_CODE_BLOCK = re.compile(r"(```.*?```|`[^`\n]+`|https?://\S+|[a-zA-Z]:\\[^\s]+)", re.DOTALL)


def clean_slop(text: str) -> str:
    """Removes AI fluff, normalizes dashes, and refines typography while protecting code spans."""
    if not text:
        return ""

    # Split text into protected tokens and prose tokens
    parts = _CODE_BLOCK.split(text)
    cleaned_parts = []

    for idx, part in enumerate(parts):
        # Odd indices are protected (code blocks, backticks, URLs)
        if idx % 2 == 1:
            cleaned_parts.append(part)
            continue

        prose = part

        # 1. Normalize em-dashes and en-dashes
        prose = prose.replace("—", " - ").replace("–", " - ")

        # 2. Strip slop phrases
        for pat, repl in SLOP_PATTERNS:
            prose = pat.sub(repl, prose)

        # 3. Clean double spaces and leading commas/spaces
        prose = re.sub(r"[ \t]+", " ", prose)
        prose = re.sub(r"\n{3,}", "\n\n", prose)

        cleaned_parts.append(prose)

    result = "".join(cleaned_parts).strip()
    # Capitalize first character if slop removal left a lowercase letter
    if result and result[0].islower():
        result = result[0].upper() + result[1:]

    return result
