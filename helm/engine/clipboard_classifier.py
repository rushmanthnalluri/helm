"""Contextual Clipboard Classifier for Helm.
Classifies clipboard content by type (Error, URL, Phone, JSON, Code, Plain Text)
and determines available high-leverage contextual actions.
"""
import re
import json

class ClipboardClassification:
    def __init__(self, content_type, action_available, suggested_action, description):
        self.content_type = content_type
        self.action_available = action_available
        self.suggested_action = suggested_action
        self.description = description

    def to_dict(self):
        return {
            'content_type': self.content_type,
            'action_available': self.action_available,
            'suggested_action': self.suggested_action,
            'description': self.description
        }

URL_PATTERN = re.compile(r"^https?://[^\s]+$")
PHONE_PATTERN = re.compile(r"^\+?\d[\d\s\-()]{6,}\d$")
TRACEBACK_PATTERN = re.compile(
    r"(?:Traceback \(most recent call last\):|"
    r"(?:SyntaxError|TypeError|ValueError|KeyError|AttributeError|IndexError|NameError|ZeroDivisionError):|"
    r"(?:NullPointerException|ArrayIndexOutOfBoundsException|ClassNotFoundException)|"
    r"FATAL ERROR|UnhandledPromiseRejection|uncaught exception|"
    r"at [A-Za-z0-9_$.]+\([A-Za-z0-9_$.]+:\d+\))",
    re.I
)
CODE_PATTERNS = re.compile(
    r"^(?:def\s+[a-zA-Z_]|class\s+[a-zA-Z_]|function\s+[a-zA-Z_]|import\s+[a-zA-Z_]|const\s+[a-zA-Z_]|let\s+[a-zA-Z_]|public\s+static|SELECT\s+.*FROM)",
    re.M
)

def classify_clipboard_content(clipboard_text):
    """Classifies text into semantic categories and returns actionable suggestions."""
    if not clipboard_text or not clipboard_text.strip():
        return ClipboardClassification("empty", False, None, "Clipboard is empty")

    text = clipboard_text.strip()

    # 1. Error / Traceback
    if TRACEBACK_PATTERN.search(text):
        return ClipboardClassification(
            content_type="error",
            action_available=True,
            suggested_action="explain_error",
            description="Programming error or traceback detected. Click to explain cause and get fix."
        )

    # 2. JSON Data
    if (text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']')):
        try:
            json.loads(text)
            return ClipboardClassification(
                content_type="json",
                action_available=True,
                suggested_action="format_json",
                description="Valid JSON payload. Click to pretty-print or inspect."
            )
        except Exception:
            return ClipboardClassification(
                content_type="malformed_json",
                action_available=True,
                suggested_action="fix_json",
                description="Malformed JSON detected. Click to find syntax error."
            )

    # 3. URL
    if URL_PATTERN.fullmatch(text):
        return ClipboardClassification(
            content_type="url",
            action_available=True,
            suggested_action="summarize_page",
            description="Web URL detected. Click to open or summarize."
        )

    # 4. Phone Number
    clean_digits = re.sub(r'[^\d+]', '', text)
    if PHONE_PATTERN.fullmatch(text) and 7 <= len(clean_digits) <= 16:
        return ClipboardClassification(
            content_type="phone_number",
            action_available=True,
            suggested_action="message_contact",
            description=f"Phone number ({clean_digits}) detected. Click to message on WhatsApp."
        )

    # 5. Code Snippet
    if CODE_PATTERNS.search(text) or (';' in text and '{' in text and '}' in text):
        return ClipboardClassification(
            content_type="code",
            action_available=True,
            suggested_action="explain_code",
            description="Code snippet detected. Click to explain or optimize."
        )

    # 6. Plain Text
    words = len(text.split())
    if words >= 40:
        return ClipboardClassification(
            content_type="long_text",
            action_available=True,
            suggested_action="summarize_text",
            description=f"Long text passage ({words} words). Click to summarize."
        )

    return ClipboardClassification("plain_text", False, None, "Short plain text")
