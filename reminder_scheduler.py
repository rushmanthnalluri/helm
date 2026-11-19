"""Scheduled Reminders and Timer System for Helm.
Stores and tracks timed reminders that survive bot and PC restarts.
"""
import os
import re
import json
import time
import uuid

CONFIG_DIR = os.environ.get('HELM_DIR') or os.path.join(os.path.expanduser('~'), '.config', 'helm')
os.makedirs(CONFIG_DIR, exist_ok=True)
REMINDERS_FILE = os.path.join(CONFIG_DIR, 'reminders.json')

DURATION_PATTERN = re.compile(r"^(\d+)\s*([smhd])$", re.I)

def parse_duration_to_seconds(duration_text):
    """Converts duration strings like '10m', '30s', '2h', '1d' to integer seconds."""
    clean = str(duration_text).strip()
    match = DURATION_PATTERN.match(clean)
    if not match:
        # Check if bare integer seconds
        if clean.isdigit():
            return int(clean)
        raise ValueError(f"Could not parse duration '{duration_text}'. Use e.g. '10m', '30s', '2h'.")

    amount, unit = match.groups()
    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    return int(amount) * multipliers[unit.lower()]

def _load_reminders():
    if os.path.exists(REMINDERS_FILE):
        try:
            with open(REMINDERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return []

def _save_reminders(items):
    with open(REMINDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(items, f, indent=2)

def add_reminder(chat_id, duration_spec, message_text):
    """Adds a new persistent reminder."""
    if isinstance(duration_spec, (int, float)):
        seconds = int(duration_spec)
        dur_label = f"{seconds}s"
    else:
        seconds = parse_duration_to_seconds(duration_spec)
        dur_label = str(duration_spec)

    reminder_id = str(uuid.uuid4())[:8]
    fire_at = time.time() + seconds

    item = {
        'id': reminder_id,
        'chat_id': str(chat_id),
        'created_at': time.time(),
        'fire_at': fire_at,
        'duration_str': dur_label,
        'message': str(message_text).strip(),
        'is_fired': False
    }

    items = _load_reminders()
    items.append(item)
    _save_reminders(items)
    return item

def get_due_reminders():
    """Returns any reminders whose fire_at timestamp has elapsed."""
    now = time.time()
    items = _load_reminders()
    due = []
    for it in items:
        if not it.get('is_fired') and it.get('fire_at', 0) <= now:
            due.append(it)
    return due

def mark_reminder_fired(reminder_id):
    """Marks a reminder as fired so it doesn't trigger again."""
    items = _load_reminders()
    for it in items:
        if it.get('id') == reminder_id:
            it['is_fired'] = True
    _save_reminders(items)

def list_active_reminders(chat_id=None):
    """Lists non-fired reminders, optionally filtered by chat_id."""
    now = time.time()
    items = _load_reminders()
    active = []
    for it in items:
        if not it.get('is_fired') and it.get('fire_at', 0) > now:
            if chat_id is None or str(it.get('chat_id')) == str(chat_id):
                active.append(it)
    return active

def cancel_reminder(reminder_id):
    """Cancels a pending reminder."""
    items = _load_reminders()
    found = False
    for it in items:
        if it.get('id') == reminder_id:
            it['is_fired'] = True
            found = True
    _save_reminders(items)
    return found
