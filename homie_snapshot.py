"""homie_snapshot.py - Page Snapshot Diffing Engine for Web & Accessibility Automation.

Tracks page changes across interactions and produces token-efficient diffs:
- Instead of transmitting the entire accessibility or DOM tree on every step (~15,000 characters),
  transmits only '+ ' new, '~ ' changed, and '- ' gone elements (~800 characters).
- Periodic full sync: resets to full snapshot every 8 actions or upon navigation to prevent drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

FULL_EVERY_N_ACTIONS = 8


@dataclass
class ElementSnapshot:
    ref_id: int
    tag: str
    name: str
    value: str = ""

    def line(self) -> str:
        val_str = f' value="{self.value}"' if self.value else ""
        return f'[{self.ref_id}] {self.tag} "{self.name}"{val_str}'


@dataclass
class SnapshotTracker:
    url: str = ""
    title: str = ""
    known_elements: dict[int, str] = field(default_factory=dict)
    actions_since_full: int = 0

    def reset(self) -> None:
        self.url = ""
        self.title = ""
        self.known_elements.clear()
        self.actions_since_full = 0

    def format_elements(self, title: str, url: str, elements: list[ElementSnapshot]) -> str:
        """Computes full snapshot or incremental diff."""
        clean_url = url.split("#", 1)[0]
        prev_clean_url = self.url.split("#", 1)[0]
        is_navigation = (clean_url != prev_clean_url) or not self.known_elements

        if is_navigation or self.actions_since_full >= FULL_EVERY_N_ACTIONS:
            # Full snapshot
            self.url = clean_url
            self.title = title
            self.known_elements = {e.ref_id: e.line() for e in elements}
            self.actions_since_full = 0

            lines = [f"Page: {title} ({url})"]
            for e in elements:
                lines.append(f"  {e.line()}")
            return "\n".join(lines)

        # Incremental diff
        self.actions_since_full += 1
        curr_map = {e.ref_id: e.line() for e in elements}

        new_refs = [e for e in elements if e.ref_id not in self.known_elements]
        changed_refs = [e for e in elements if e.ref_id in self.known_elements and self.known_elements[e.ref_id] != e.line()]
        removed_ids = [rid for rid in self.known_elements if rid not in curr_map]

        # If diff is substantial, fallback to full snapshot
        if len(new_refs) + len(changed_refs) + len(removed_ids) > len(elements) // 2:
            self.known_elements = curr_map
            self.actions_since_full = 0
            lines = [f"Page: {title} ({url})"]
            for e in elements:
                lines.append(f"  {e.line()}")
            return "\n".join(lines)

        diff_lines = [f"Page changes: {title}"]
        for nr in new_refs:
            diff_lines.append(f"  + {nr.line()}")
        for cr in changed_refs:
            diff_lines.append(f"  ~ {cr.line()}")
        for r_id in removed_ids:
            old_line = self.known_elements[r_id]
            diff_lines.append(f"  - {old_line}")

        # Update tracker
        self.known_elements = curr_map
        return "\n".join(diff_lines)
