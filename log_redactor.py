"""log_redactor.py - Privacy Redaction and PII Sanitization for Homie.

Sanitizes audit ledgers, logs, crash dumps, and telemetry traces:
- Masks API keys (OpenAI, Gemini, Anthropic, NVIDIA, Groq).
- Masks high-risk authentication tokens, INTENT tokens, and step-up IDs.
- Masks email addresses, credit cards, SSNs, and passwords.
- Protects user privacy while retaining diagnostic utility.
"""

import re
from typing import Any, Dict, List, Union

REDACTION_PATTERNS = [
    # API Keys & Secrets
    (re.compile(r'(?i)(?:api_key|apikey|secret|password|passwd|token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?'), r'***REDACTED_SECRET***'),
    # Bearer / Authorization headers
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}'), r'Bearer ***REDACTED_TOKEN***'),
    # Homie Cryptographic Intent & Lease Tokens
    (re.compile(r'INTENT_V\d:[a-zA-Z0-9_\-:]+'), r'***REDACTED_INTENT_TOKEN***'),
    (re.compile(r'LEASE:[a-zA-Z0-9_\-]+'), r'***REDACTED_LEASE_TOKEN***'),
    # Credit Cards (13-16 digits formatted)
    (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), r'***REDACTED_CC***'),
    # US Social Security Numbers
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), r'***REDACTED_SSN***'),
    # Email Addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), r'***REDACTED_EMAIL***'),
]


def redact_string(text: str) -> str:
    """Sanitizes text by masking PII, tokens, and credentials."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_structure(data: Union[Dict, List, Any]) -> Union[Dict, List, Any]:
    """Recursively redacts sensitive values inside nested dicts, lists, and structures."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("password", "secret", "api_key", "token", "private_key", "auth")):
                cleaned[k] = "***REDACTED_FIELD***"
            else:
                cleaned[k] = redact_structure(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_structure(item) for item in data]
    elif isinstance(data, str):
        return redact_string(data)
    else:
        return data
