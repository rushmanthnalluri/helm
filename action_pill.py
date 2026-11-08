"""Floating Action Pill and Contextual Action Resolver for Homie.
Maps classified clipboard entities into high-leverage desktop actions
and provides quick keyboard/button handlers.
"""
import json
import webbrowser
import windows_tools
import pyperclip

ACTION_MAP = {
    'error': [
        {'id': 'explain_error', 'label': '💡 Explain Error', 'description': 'Analyze error with AI brain'},
        {'id': 'search_error', 'label': '🔍 Search Solution', 'description': 'Search solution in browser'},
    ],
    'url': [
        {'id': 'open_url', 'label': '🌐 Open in Browser', 'description': 'Open link in default browser'},
        {'id': 'copy_clean_url', 'label': '📋 Copy Clean URL', 'description': 'Strip tracking parameters and copy'},
    ],
    'json': [
        {'id': 'format_json', 'label': '✨ Pretty Print', 'description': 'Format and indent JSON'},
        {'id': 'minify_json', 'label': '📦 Minify JSON', 'description': 'Minify JSON to single line'},
    ],
    'phone_number': [
        {'id': 'whatsapp_phone', 'label': '💬 WhatsApp Chat', 'description': 'Open WhatsApp chat with contact'},
        {'id': 'copy_digits', 'label': '📋 Copy Pure Digits', 'description': 'Copy sanitized phone digits'},
    ],
    'code': [
        {'id': 'explain_code', 'label': '📝 Explain Code', 'description': 'Explain logic & purpose with AI'},
        {'id': 'copy_formatted', 'label': '📋 Clean Indent', 'description': 'Format indentation'},
    ],
    'plain_text': [
        {'id': 'speak_text', 'label': '🔊 Read Aloud', 'description': 'Speak text via offline SAPI voice'},
        {'id': 'word_count', 'label': '📊 Word Count', 'description': 'Inspect word and character count'},
    ]
}

def get_actions_for_classification(classification) -> list[dict]:
    """Returns available action descriptors for a given ClipboardClassification."""
    if not classification:
        return []

    c_type = getattr(classification, 'content_type', None)
    if not c_type and isinstance(classification, dict):
        c_type = classification.get('content_type')

    return ACTION_MAP.get(str(c_type).lower(), [])

def execute_action(action_id: str, content: str) -> tuple[bool, str]:
    """Executes a contextual action on the supplied content."""
    text = (content or "").strip()
    if not text:
        return False, "Content is empty."

    if action_id == 'open_url':
        webbrowser.open(text)
        return True, f"Opened URL in browser: {text}"

    elif action_id == 'copy_clean_url':
        import urllib.parse
        parsed = urllib.parse.urlsplit(text)
        q_params = urllib.parse.parse_qsl(parsed.query)
        # Filter out common tracking query params
        clean_params = [(k, v) for k, v in q_params if not (k.startswith('utm_') or k in ('fbclid', 'gclid', 'ref'))]
        new_query = urllib.parse.urlencode(clean_params)
        clean_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
        pyperclip.copy(clean_url)
        return True, f"Copied clean URL to clipboard: {clean_url}"

    elif action_id == 'format_json':
        try:
            data = json.loads(text)
            formatted = json.dumps(data, indent=2)
            pyperclip.copy(formatted)
            return True, "Formatted JSON and copied to clipboard."
        except Exception as e:
            return False, f"Invalid JSON: {e}"

    elif action_id == 'minify_json':
        try:
            data = json.loads(text)
            minified = json.dumps(data, separators=(',', ':'))
            pyperclip.copy(minified)
            return True, "Minified JSON and copied to clipboard."
        except Exception as e:
            return False, f"Invalid JSON: {e}"

    elif action_id == 'whatsapp_phone':
        digits = "".join(ch for ch in text if ch.isdigit() or ch == '+')
        ok, msg = windows_tools.send_whatsapp_message(digits, "")
        return ok, msg

    elif action_id == 'copy_digits':
        digits = "".join(ch for ch in text if ch.isdigit() or ch == '+')
        pyperclip.copy(digits)
        return True, f"Copied phone digits to clipboard: {digits}"

    elif action_id == 'search_error':
        import urllib.parse
        first_line = text.splitlines()[-1] if text else "Error"
        query_url = f"https://www.google.com/search?q={urllib.parse.quote(first_line)}"
        webbrowser.open(query_url)
        return True, f"Searching solution for: {first_line}"

    elif action_id == 'word_count':
        words = len(text.split())
        chars = len(text)
        return True, f"Length: {chars} characters, {words} words, {len(text.splitlines())} lines."

    return False, f"Unknown action '{action_id}'."
