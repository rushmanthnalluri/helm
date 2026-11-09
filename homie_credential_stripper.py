"""homie_credential_stripper.py - Secret and Credential Redaction Filter for Homie.

Scans text, tool parameters, outputs, and log entries to redact sensitive credentials,
API keys, bearer tokens, private keys, and single-use cryptographic secrets before
they can leak to untrusted model context, UI displays, or persistent logs.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple, Union

_CREDENTIAL_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("api_key", re.compile(r"(?:sk-[a-zA-Z0-9_\-]{20,}|AIzaSy[a-zA-Z0-9_\-]{33})")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9a-zA-Z\-]+")),
    ("bearer_token", re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}")),
    ("twilio_sid", re.compile(r"AC[a-f0-9]{32}")),
    ("homie_approval_token", re.compile(r"tok_[a-f0-9]{32}")),
    ("homie_step_up_token", re.compile(r"step_up_[a-f0-9]{32}")),
]


class CredentialStripper:
    """Scans and redacts credentials from arbitrary text or structured objects."""

    def __init__(self, patterns: List[Tuple[str, re.Pattern[str]]] | None = None) -> None:
        self._patterns = patterns or _CREDENTIAL_PATTERNS

    def strip(self, text: str) -> str:
        """Redact sensitive patterns in text string."""
        if not text or not isinstance(text, str):
            return text
        result = text
        for label, pattern in self._patterns:
            result = pattern.sub(f"[REDACTED:{label}]", result)
        return result

    def strip_object(self, obj: Any) -> Any:
        """Recursively redact secrets in dictionaries, lists, and strings."""
        if isinstance(obj, str):
            return self.strip(obj)
        elif isinstance(obj, dict):
            return {k: self.strip_object(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.strip_object(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self.strip_object(item) for item in obj)
        return obj


_GLOBAL_STRIPPER = CredentialStripper()


def redact_secrets(content: Union[str, Dict[str, Any], List[Any]]) -> Union[str, Dict[str, Any], List[Any]]:
    """Convenience helper to redact secrets using global stripper."""
    return _GLOBAL_STRIPPER.strip_object(content)
