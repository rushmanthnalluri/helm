#!/usr/bin/env python3
"""Homie: A fast, private, hold-to-talk desktop AI assistant for Windows.
Powered by your Claude Pro/Max subscription or local models.
Inspired by Atticus, rebuilt from the ground up for Windows.

Usage:
  homie.py "what's on my screen?"      Run one request (or voice query)
  homie.py --place <app> <position>    Snap window (left, right, full, center)
  homie.py --look                      Capture displays and print paths
  homie.py --search <query>            Free web search (DuckDuckGo)
  homie.py --read <url>                Fetch webpage as plain text
  homie.py --fast "<words>"            Execute instant local command (0ms, no AI)
  homie.py --remember "<rule>"         Save a persistent user rule
  homie.py --forget "<words>"          Remove a saved rule
  homie.py --hands <action> ...        Simulate mouse/keyboard actions
  homie.py --media <action>            Control media (play, pause, next, volup)
  homie.py --gate                      Pre-tool execution safety filter
"""
import os
import sys
import re
import json
import time
import shutil
import urllib.parse
import urllib.request
import webbrowser
import subprocess
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Add homie directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

# Data and config directories
HOME = os.path.expanduser('~')
CONFIG_DIR = os.environ.get('HOMIE_DIR') or os.path.join(HOME, '.config', 'homie')
os.makedirs(CONFIG_DIR, exist_ok=True)

PREFS_FILE = os.path.join(CONFIG_DIR, 'settings.json')
MEMORY_FILE = os.path.join(CONFIG_DIR, 'memory.md')
RECENT_FILE = os.path.join(CONFIG_DIR, 'recent.jsonl')
LOG_FILE = os.path.join(CONFIG_DIR, 'log.jsonl')
ME_FILE = os.path.join(CONFIG_DIR, 'me.json')
MACROS_FILE = os.path.join(CONFIG_DIR, 'macros.json')

DEFAULT_PREFS = {
    "hotkey": "ctrl+alt+space",
    "hotkeyMode": "hold",       # "hold" or "toggle"
    "provider": "gemini",       # "gemini" (Google AI Studio), "nvidia" (NVIDIA NIM), "groq", "ollama", "claude"
    "model": "gemini-flash-lite-latest", # high-availability free tier model
    "safe": True,               # Safe mode blocks outgoing chat messages
    "whisperModel": "small",    # "small" (244M, high accuracy), "base", "tiny"
    "whisperLanguage": "en",
    "speak": False,
    "instant": True,            # Instant local commands without AI
    "geminiKey": "",            # Google AI Studio free API key
    "nvidiaKey": "",            # NVIDIA NIM free API key
    "groqKey": "",              # Groq free API key
    "apiBase": "",
    "apiKey": ""
}

def get_prefs():
    """Loads user preferences or default settings."""
    if os.path.exists(PREFS_FILE):
        try:
            with open(PREFS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return {**DEFAULT_PREFS, **data}
        except Exception:
            pass
    return DEFAULT_PREFS.copy()

def save_pref(key, value):
    """Saves a preference key-value pair."""
    prefs = get_prefs()
    prefs[key] = value
    with open(PREFS_FILE, 'w', encoding='utf-8') as f:
        json.dump(prefs, f, indent=2)

def get_rules():
    """Returns saved persistent user rules."""
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            pass
    return []

def add_rule(rule):
    """Adds a persistent user rule."""
    rules = get_rules()
    if rule not in rules:
        with open(MEMORY_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n{rule}")
    return f"Remembered: '{rule}'"

def remove_rule(words):
    """Removes rules containing words."""
    rules = get_rules()
    kept = [r for r in rules if words.lower() not in r.lower()]
    with open(MEMORY_FILE, 'w', encoding='utf-8') as f:
        f.write("# Homie Memory Rules\n" + "\n".join(kept) + "\n")
    return f"Removed {len(rules) - len(kept)} rule(s)."

def log_event(event_type, details):
    """Appends an event to the log file."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            record = {'timestamp': time.time(), 'type': event_type, **details}
            f.write(json.dumps(record) + '\n')
    except Exception:
        pass

# ----------------- Workflow Macro Engine -----------------

DEFAULT_MACROS = {
    "code": [
        {"action": "open", "target": "code"},
        {"action": "snap", "where": "left", "app": "code"}
    ],
    "browser": [
        {"action": "open", "target": "chrome"},
        {"action": "snap", "where": "right", "app": "chrome"}
    ],
    "dev": [
        {"action": "open", "target": "code"},
        {"action": "open", "target": "wt"},
        {"action": "snap", "where": "left", "app": "code"},
        {"action": "snap", "where": "right", "app": "wt"}
    ],
    "relax": [
        {"action": "play", "query": "lofi hip hop radio"},
        {"action": "open", "target": "spotify"}
    ]
}

def get_macros():
    """Loads saved workflow macros from disk."""
    if os.path.exists(MACROS_FILE):
        try:
            with open(MACROS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return DEFAULT_MACROS.copy()

def save_macro(name, steps):
    """Saves a workflow macro."""
    macros = get_macros()
    macros[name.lower().strip()] = steps
    with open(MACROS_FILE, 'w', encoding='utf-8') as f:
        json.dump(macros, f, indent=2)
    return f"Saved macro '{name}' with {len(steps)} steps."

def delete_macro(name):
    """Deletes a workflow macro."""
    macros = get_macros()
    clean_name = name.lower().strip()
    if clean_name in macros:
        del macros[clean_name]
        with open(MACROS_FILE, 'w', encoding='utf-8') as f:
            json.dump(macros, f, indent=2)
        return True, f"Deleted macro '{clean_name}'."
    return False, f"Macro '{clean_name}' not found."

def execute_macro(name, caller_id="desktop_user"):
    """Executes a workflow macro sequentially through ActionBroker and skill_compiler."""
    clean_name = name.lower().strip()

    # 1. Check skill_compiler registry (HMAC-SHA256 signed macros)
    try:
        import skill_compiler
        reg = skill_compiler.get_macro_registry()
        if reg.get_macro(clean_name):
            ok, msg, _ = skill_compiler.execute_compiled_macro(clean_name, caller_id=caller_id, registry=reg)
            return ok, msg
    except Exception:
        pass

    # 2. Legacy macros routed through ActionBroker
    macros = get_macros()
    if clean_name not in macros:
        return False, f"Macro '{clean_name}' not found. Available macros: {', '.join(macros.keys())}"

    import action_broker
    steps = macros[clean_name]
    executed = 0
    for step in steps:
        act = step.get('action', '').lower()
        if act == 'open':
            action_broker.execute_action('homie_launch_app', {'app_name': step.get('target', '')}, caller_id=f"macro:{clean_name}")
            executed += 1
        elif act == 'snap':
            action_broker.execute_action('homie_place_window', {'app_name': step.get('app', ''), 'position': step.get('where', 'full')}, caller_id=f"macro:{clean_name}")
            executed += 1
        elif act == 'play':
            action_broker.execute_action('homie_play_youtube', {'query': step.get('query', '')}, caller_id=f"macro:{clean_name}")
            executed += 1
        elif act == 'media':
            action_broker.execute_action('homie_control_media', {'action': step.get('action', 'play_pause')}, caller_id=f"macro:{clean_name}")
            executed += 1
        elif act == 'cmd':
            action_broker.execute_action('homie_safe_command', {'command': step.get('command', '')}, caller_id=f"macro:{clean_name}")
            executed += 1
        elif act == 'sleep':
            time.sleep(float(step.get('seconds', 0.5)))
        time.sleep(0.1)

    return True, f"Executed macro '{clean_name}' ({executed} steps completed)."

# ----------------- Contextual Smart Clipboard Copilot -----------------

def analyze_clipboard(custom_text=None):
    """Contextual Smart Clipboard Copilot:
    Inspects clipboard content, categorizes it (URL, Error/Traceback, Code, JSON, Phone, Text),
    and generates actionable explanations and suggestions.
    """
    text = custom_text if custom_text is not None else windows_tools.get_clipboard_text()
    if not text or not text.strip():
        return "📋 Clipboard is currently empty."

    stripped = text.strip()

    # 1. Error / Stack Trace / Exception
    error_patterns = [
        r'Traceback \(most recent call last\):',
        r'(?:SyntaxError|TypeError|ValueError|KeyError|AttributeError|IndexError|NameError|ZeroDivisionError):',
        r'(?:NullPointerException|ArrayIndexOutOfBoundsException|ClassNotFoundException)',
        r'FATAL ERROR|UnhandledPromiseRejection|uncaught exception',
        r'(?:Error|Exception|Fail|FAILED):',
        r'at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_$.]+:\d+\)'
    ]
    if any(re.search(pat, stripped, re.I) for pat in error_patterns):
        import ai_engine
        prompt = f"Analyze this programming error/traceback. Explain why it occurred in 2 concise sentences, and provide the exact fix:\n\n```\n{stripped[:2000]}\n```"
        prefs = get_prefs()
        analysis = ai_engine.run_query(prompt, prefs)
        return f"🚨 **Error Detected in Clipboard**:\n\n{analysis}\n\n*Snippet:*\n```\n{stripped[:250]}...\n```"

    # 2. JSON Data
    if (stripped.startswith('{') and stripped.endswith('}')) or (stripped.startswith('[') and stripped.endswith(']')):
        try:
            parsed = json.loads(stripped)
            formatted = json.dumps(parsed, indent=2)
            return f"📦 **Valid JSON Detected** ({len(stripped)} chars):\n```json\n{formatted[:1200]}\n```"
        except Exception as e:
            return f"⚠️ **Malformed JSON in Clipboard**:\nSyntax error: {e}\n```\n{stripped[:400]}\n```"

    # 3. URL
    url_match = re.search(r'https?://[^\s]+', stripped)
    if url_match:
        url = url_match.group(0)
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        return f"🔗 **URL Detected in Clipboard**:\n• Target: `{url}`\n• Domain: **{domain}**\n\nTip: Send `/play {url}` to open, or ask Homie to inspect it."

    # 4. Phone Number
    clean_phone = re.sub(r'[^\d+]', '', stripped)
    if re.match(r'^\+?\d{7,15}$', clean_phone) and 7 <= len(clean_phone) <= 15:
        return f"📞 **Phone Number Detected**:\n`{clean_phone}`\n\nQuick Action: Use `/msg whatsapp {clean_phone} <message>` to chat."

    # 5. Code Snippet
    code_markers = ('def ', 'class ', 'function', 'import ', 'return ', 'const ', 'let ', 'public static', '<div>', 'SELECT ', 'INSERT ')
    if any(m in stripped for m in code_markers):
        import ai_engine
        prompt = f"Explain what this code does in 2 concise sentences, noting any potential bugs:\n\n```\n{stripped[:1500]}\n```"
        prefs = get_prefs()
        explanation = ai_engine.run_query(prompt, prefs)
        return f"💻 **Code Snippet Detected**:\n\n{explanation}\n\n*Code:*\n```\n{stripped[:300]}...\n```"

    # 6. General Text Note
    words = len(stripped.split())
    chars = len(stripped)
    preview = stripped[:400] + ("..." if len(stripped) > 400 else "")
    return (
        f"📋 **Clipboard Content**:\n"
        f"• Stats: {words} words, {chars} characters\n\n"
        f"```\n{preview}\n```"
    )

# ----------------- Fast Local Instant Commands (< 50ms) -----------------

def try_fast_command(text, caller_id="desktop_user"):
    import action_broker
    """
    Attempts to execute simple commands locally without invoking AI.
    Returns (handled, output_string).
    """
    # 1. Clean punctuation and conversational filler
    raw = text.strip()
    t = re.sub(r'^[,\.\s!?\'"]+|[,\.\s!?\'"]+$', '', raw.lower()).strip()
    t = re.sub(r'^(?:hey\s+homie|homie|please|i\s*said|can\s+you|could\s+you)\s*[,:]?\s*', '', t).strip()
    t = re.sub(r'^[,\.\s!?\'"]+|[,\.\s!?\'"]+$', '', t).strip()

    if not t:
        return False, ""

    # Note: Pairing ceremony was deliberately removed from voice/fast-command processing
    # to prevent acoustic injection attacks (e.g. ambient video/speech triggering enrollment).
    # Mobile pairing requires local physical presence: Ctrl+Alt+P or Console HUD.

    # 2. Media Hardware Controls (play/pause, next, prev, volume)
    media_patterns = {
        r'^(pause|resume)(\s+music|\s+song|\s+track)?$': 'play_pause',
        r'^play(\s+music|\s+song|\s+track)?$': 'play_pause',
        r'^(next|skip)(\s+song|\s+track)?$': 'next',
        r'^(prev|previous)(\s+song|\s+track)?$': 'prev',
        r'^(mute|unmute)$': 'mute',
        r'^(volume\s+up|louder)$': 'volup',
        r'^(volume\s+down|quieter)$': 'voldown',
    }
    for pat, action in media_patterns.items():
        if re.search(pat, t):
            ok, msg, _ = action_broker.execute_action('homie_control_media', {'action': action}, caller_id=caller_id)
            return True, msg

    # 3. YouTube Search & Playback (e.g. "open youtube and play the loose songs", "open yt and play telugu music")
    yt_matched = False
    yt_query = None

    # "open youtube/yt and play <query>" or "open youtube/yt to play <query>"
    m1 = re.match(r'^(?:open\s+)?(?:youtube|yt)\s+(?:and\s+|to\s+)?(?:play|search(?:\s+for)?)\s*(.*)$', t)
    if m1:
        yt_matched = True
        yt_query = m1.group(1).strip()

    # "play <query> on youtube/yt"
    if not yt_matched:
        m2 = re.match(r'^play\s+(.*?)\s+(?:on|in)\s+(?:youtube|yt)$', t)
        if m2:
            yt_matched = True
            yt_query = m2.group(1).strip()

    # "search/find <query> on youtube/yt" or "search youtube for <query>"
    if not yt_matched:
        m3 = re.match(r'^(?:search|find)\s+(?:on\s+)?(?:youtube|yt)\s+(?:for\s+)?(.*)$', t)
        if m3:
            yt_matched = True
            yt_query = m3.group(1).strip()

    # Just "open youtube" or "open yt" or "youtube"
    if not yt_matched:
        if re.match(r'^(?:open\s+)?(?:youtube|yt)$', t):
            yt_matched = True
            yt_query = ""

    # "youtube <query>" or "yt <query>"
    if not yt_matched:
        m5 = re.match(r'^(?:youtube|yt)\s+(.*)$', t)
        if m5:
            yt_matched = True
            yt_query = m5.group(1).strip()

    if yt_matched:
        ok, msg, _ = action_broker.execute_action('homie_play_youtube', {'query': yt_query}, caller_id=caller_id)
        return True, msg

    # 4. Generic Song Playback (e.g. "play bohemian rhapsody", "play loose songs", "play telugu songs")
    play_match = re.match(r'^play\s+(.+)$', t)
    if play_match:
        target_song = play_match.group(1).strip()
        if target_song not in ('music', 'song', 'audio', 'sound', 'track', 'media', 'it'):
            ok, msg, _ = action_broker.execute_action('homie_play_youtube', {'query': target_song}, caller_id=caller_id)
            return True, msg

    # 5. Window Placement (e.g. "put this on left", "window right", "maximize")
    place_patterns = [
        (r'\b(left|left half|left side)\b', 'left'),
        (r'\b(right|right half|right side)\b', 'right'),
        (r'\b(full|fullscreen|maximize|maximized)\b', 'full'),
        (r'\b(center|middle)\b', 'center'),
        (r'\b(minimize|hide window)\b', 'minimize'),
    ]
    if any(k in t for k in ('window', 'put', 'snap', 'move', 'place', 'screen')) and any(re.search(pat, t) for pat, _ in place_patterns):
        for pat, where in place_patterns:
            if re.search(pat, t):
                app = ""
                for candidate in ('chrome', 'edge', 'notepad', 'spotify', 'code', 'terminal', 'explorer', 'slack'):
                    if candidate in t:
                        app = candidate
                        break
                ok, msg, _ = action_broker.execute_action('homie_place_window', {'app_name': app, 'position': where}, caller_id=caller_id)
                return True, msg

    # 6. Messaging: WhatsApp & Telegram ("open whatsapp and say hi to Rusman", "open whatsapp and say hi to amma❤️")
    clean_msg_text = re.sub(r'^[,\.\s!?\'"]+|[,\.\s!?\'"]+$', '', raw).strip()

    # A. "open <app> and say/send <text> to <recipient>"
    msg_m1 = re.search(r'^(?:open\s+)?(whatsapp|telegram)\s+(?:and\s+|to\s+)?(?:say|send|text|message)\s+(.+?)\s+to\s+(.+)$', clean_msg_text, re.I)
    if msg_m1:
        ok, res, _ = action_broker.execute_action('homie_send_chat', {'app': msg_m1.group(1), 'recipient': msg_m1.group(3).strip(), 'message': msg_m1.group(2).strip()}, caller_id=caller_id)
        return True, res

    # B. "open <app> and say/send [to] <recipient> <text>"
    msg_m2 = re.search(r'^(?:open\s+)?(whatsapp|telegram)\s+(?:and\s+|to\s+)?(?:say|send|text|message)\s+(?:to\s+)?([a-zA-Z0-9_\u0080-\uffff]+)\s+(.+)$', clean_msg_text, re.I)
    if msg_m2:
        ok, res, _ = action_broker.execute_action('homie_send_chat', {'app': msg_m2.group(1), 'recipient': msg_m2.group(2).strip(), 'message': msg_m2.group(3).strip()}, caller_id=caller_id)
        return True, res

    # C. "say/send <text> to <recipient> on <app>"
    msg_m3 = re.search(r'^(?:say|send|text|message)\s+(.+?)\s+to\s+(.+?)\s+(?:on|via|in)\s+(whatsapp|telegram)$', clean_msg_text, re.I)
    if msg_m3:
        ok, res, _ = action_broker.execute_action('homie_send_chat', {'app': msg_m3.group(3), 'recipient': msg_m3.group(2).strip(), 'message': msg_m3.group(1).strip()}, caller_id=caller_id)
        return True, res

    # D. "open <app> and say/type/send <text>" (active chat)
    msg_m4 = re.search(r'^(?:open\s+)?(whatsapp|telegram)\s+(?:and\s+|to\s+)?(?:say|type|send)\s+(.+)$', clean_msg_text, re.I)
    if msg_m4:
        ok, res, _ = action_broker.execute_action('homie_send_chat', {'app': msg_m4.group(1), 'recipient': '', 'message': msg_m4.group(2).strip()}, caller_id=caller_id)
        return True, res

    # 7. Close App ("close whatsapp", "close notepad", "exit chrome")
    close_m = re.match(r'^(?:close|quit|kill|exit)\s+([a-zA-Z0-9\s._-]+)$', t)
    if close_m:
        target = close_m.group(1).strip()
        ok, msg, _ = action_broker.execute_action('homie_close_app', {'app_name': target}, caller_id=caller_id)
        return True, msg

    # 8. PC Vitals ("pc status", "system status", "vitals", "how is my pc", "is my pc ok")
    if re.search(r'\b(pc\s+status|system\s+status|pc\s+vitals|system\s+health|how\s+is\s+my\s+pc|how\s+is\s+my\s+computer|is\s+my\s+pc\s+ok(?:ay)?|is\s+my\s+computer\s+ok(?:ay)?|^vitals$|^diagnose$|health\s+check)\b', t):
        v = windows_tools.get_system_vitals()
        msg = (
            f"💻 **PC Health Snapshot**:\n"
            f"• 🧠 RAM: {v['ram_pct']}% used ({v['ram_avail_gb']} GB free / {v['ram_total_gb']} GB)\n"
            f"• 💽 Disk (C:): {v['disk_free_gb']} GB free / {v['disk_total_gb']} GB\n"
            f"• 🔋 Power: {v['battery']}\n"
            f"• ⏱️ Uptime: {v['uptime_hours']} hours\n"
            f"• 🪟 Active: {v['active_window']}"
        )
        return True, msg

    # 9. Clipboard Inspection & Setting
    if re.search(r'\b(smart\s+clipboard|analyze\s+clipboard|smartclip|check\s+clipboard|explain\s+clipboard)\b', t):
        analysis = analyze_clipboard()
        return True, analysis

    if re.search(r'\b(what\'?s?\s+in\s+my\s+clipboard|read\s+clipboard|get\s+clipboard|clipboard\s+content|^clipboard$)\b', t):
        clip = windows_tools.get_clipboard_text()
        if clip:
            return True, f"📋 **PC Clipboard**:\n```\n{clip[:1000]}\n```"
        return True, "📋 Clipboard is currently empty."

    clip_set_m = re.match(r'^(?:copy|set\s+clipboard)\s+(?:this\s+)?(?:to\s+clipboard\s+)?(.+)$', t)
    if clip_set_m and 'to clipboard' in t:
        text_to_copy = re.sub(r'\s+to\s+clipboard.*$', '', clip_set_m.group(1)).strip()
        if text_to_copy:
            ok, msg, _ = action_broker.execute_action('homie_set_clipboard', {'text': text_to_copy}, caller_id=caller_id)
            return True, f"📋 {msg}"

    # 10. Workflow Macros
    macro_m = re.match(r'^(?:run\s+macro|macro|trigger\s+macro)\s+([a-zA-Z0-9_-]+)$', t)
    if macro_m:
        ok, msg = execute_macro(macro_m.group(1), caller_id=caller_id)
        return True, msg

    if re.search(r'\b(list\s+macros|show\s+macros|^macros$)\b', t):
        all_macros = {}
        try:
            import skill_compiler
            for m in skill_compiler.get_macro_registry().list_macros():
                all_macros[m["name"]] = m.get("steps", [])
        except Exception:
            pass
        for k, v in get_macros().items():
            if k not in all_macros:
                all_macros[k] = v

        if not all_macros:
            return True, "📜 **Workflow Macros**: No macros registered yet."

        items = "\n".join(f"• `{name}` ({len(steps)} steps)" for name, steps in all_macros.items())
        return True, f"📜 **Workflow Macros**:\n{items}\n\nUse 'run macro <name>' or `/macro <name>` to execute."

    # 11. Recent Downloads
    if re.search(r'\b(recent\s+downloads|my\s+downloads|show\s+downloads|^downloads$)\b', t):
        dl = windows_tools.list_downloads(limit=8)
        if not dl:
            return True, "📁 Downloads folder is empty."
        items = "\n".join(f"• `{d['name']}` ({d['size_mb']} MB, {d['mtime']})" for d in dl)
        return True, f"📁 **Recent Downloads**:\n{items}"

    # 11. Screen Inspection ("what's on my screen", "inspect screen", "look at my screen")
    if re.search(r'\b(what\'?s?\s+on\s+my\s+screen|inspect\s+(?:my\s+)?screen|look\s+at\s+(?:my\s+)?screen|describe\s+(?:my\s+)?screen|read\s+(?:my\s+)?screen)\b', t):
        screens = windows_tools.capture_screens()
        if screens and os.path.exists(screens[0]):
            import ai_engine
            analysis = ai_engine.run_gemini_vision("Describe what is shown on this screen, noting any open windows, applications, errors, or active tasks.", screens[0])
            return True, f"🖥️ **Screen Analysis**:\n{analysis}"
        return True, "Could not capture display for screen analysis."

    # 13. What Did I Miss / Catch-Up
    if re.search(r'\b(what\s+did\s+i\s+miss|what\s+happened\s+while\s+i\s+was\s+away|catch\s*up\s*(?:brief)?|recent\s+events)\b', t):
        import event_log
        events = event_log.get_events_since(time.time() - (4 * 3600), limit=15)
        if not events:
            return True, "✨ All quiet: No alerts or notable events recorded in the last 4 hours."
        lines = ["📋 **Recent System Timeline (Past 4 Hours)**:"]
        for e in events:
            t_str = time.strftime("%I:%M %p", time.localtime(e['occurred_at']))
            lines.append(f"• `{t_str}`: {e['event_summary']}")
        return True, "\n".join(lines)

    # 14. Local File Search ("find file <x>", "search file <x>")
    find_m = re.match(r'^(?:find|search|locate)(?:\s+for)?\s+(?:file|document|pdf)?\s*([a-zA-Z0-9_.-]+)$', t)
    if find_m and find_m.group(1).strip() not in ('youtube', 'yt', 'web', 'google', 'bing'):
        target_name = find_m.group(1).strip()
        import file_indexer
        matches = file_indexer.search_files(target_name, limit=6)
        if not matches:
            file_indexer.build_file_index()
            matches = file_indexer.search_files(target_name, limit=6)
        if matches:
            items = "\n".join(f"• `{m['file_name']}` ({file_indexer.format_file_size(m['size_bytes'])})" for m in matches)
            return True, f"🔍 **Found {len(matches)} match(es)**:\n{items}"
        return True, f"🔍 No files found matching '{target_name}' across Desktop, Downloads, and Documents."

    # 15. Top Resource Consumers ("top processes", "resource hogs", "top tasks")
    if re.search(r'\b(top\s+processes|top\s+tasks|resource\s+hogs|cpu\s+hogs|ram\s+hogs)\b', t):
        procs = windows_tools.get_top_processes(limit=5)
        if procs:
            lines = ["📊 **Top Resource Consumers**:\n"]
            for p in procs:
                lines.append(f"• `{p['name']}`: {p['mem_pct']}% RAM ({p['mem_mb']} MB) | {p['cpu_pct']}% CPU")
            return True, "\n".join(lines)

    # 16. Focus Report / Screen Time ("focus report", "screen time", "productivity report")
    if re.search(r'\b(focus\s+report|screen\s*time|productivity\s+report|my\s+screen\s*time)\b', t):
        import focus_tracker
        rep = focus_tracker.get_focus_report(lookback_hours=24)
        if not rep:
            return True, "🖥️ **Focus Report**: No window activity recorded in the past 24 hours."
        lines = ["🖥️ **PC Productivity Focus Report (Past 24h)**:"]
        for r in rep:
            lines.append(f"• `{r['application_name']}`: {r['formatted_duration']} ({r['percent']}%)")
        return True, "\n".join(lines)

    # 17. Meeting Notes ("start meeting notes", "stop meeting notes", "end meeting")
    if re.search(r'\b(start\s+(?:recording\s+)?meeting(?:\s+notes)?|record\s+meeting)\b', t):
        import meeting_notes
        sess = meeting_notes.get_meeting_session()
        ok, msg = sess.start_meeting("Voice Initiated Meeting")
        return True, msg

    if re.search(r'\b(stop\s+meeting(?:\s+notes)?|end\s+meeting(?:\s+notes)?|finish\s+meeting)\b', t):
        import meeting_notes
        sess = meeting_notes.get_meeting_session()
        ok, res = sess.stop_meeting()
        if not ok:
            return True, f"⚠️ {res}"
        return True, res['summary']

    # 18. Assistant Timeline Summary ("what did i miss", "timeline summary", "catch me up")
    if re.search(r'\b(what\s+did\s+i\s+miss|catch\s+me\s+up|timeline\s+summary|assistant\s+timeline)\b', t):
        import assistant_timeline
        return True, assistant_timeline.get_what_did_i_miss_summary(lookback_hours=4)

    # 19. Workspace Layout Presets
    ws_save_m = re.match(r'^(?:save\s+workspace\s+(?:as\s+)?|save\s+layout\s+(?:as\s+)?)([a-zA-Z0-9_-]+)$', t)
    if ws_save_m:
        import workspace_manager
        pname = ws_save_m.group(1).strip()
        ok, msg, _ = workspace_manager.save_workspace_preset(pname)
        return True, msg

    ws_restore_m = re.match(r'^(?:switch\s+to\s+([a-zA-Z0-9_-]+)\s+workspace|(?:restore|load)\s+(?:workspace\s+)?([a-zA-Z0-9_-]+))$', t)
    if ws_restore_m:
        import workspace_manager
        pname = (ws_restore_m.group(1) or ws_restore_m.group(2)).strip()
        ok, msg, _ = workspace_manager.restore_workspace_preset(pname)
        return True, msg

    # 19. Quick Notes & Scratchpad
    note_add_m = re.match(r'^(?:take\s+note|quick\s+note|save\s+note|add\s+note)\s+(.+)$', t)
    if note_add_m:
        import quick_notes
        text = note_add_m.group(1).strip()
        nid = quick_notes.save_quick_note(text)
        return True, f"📝 Saved note #{nid}: \"{text}\""

    if re.search(r'\b(show\s+notes|list\s+notes|my\s+notes|scratchpad)\b', t):
        import quick_notes
        notes = quick_notes.get_recent_notes(limit=6)
        if not notes:
            return True, "📝 No notes in scratchpad. Use 'take note <text>' to save one."
        lines = ["📝 **Recent Scratchpad Notes**:"]
        for n in notes:
            pin_icon = "📌 " if n['is_pinned'] else ""
            lines.append(f"• {pin_icon}`#{n['id']}`: {n['note_text']}")
        return True, "\n".join(lines)

    # 20. Quick App / Website Launch (e.g. "open notepad", "launch chrome", "open spotify", "open github")
    m = re.match(r'^(?:open|launch|start|run)\s+([a-zA-Z0-9\s._-]+)$', t)
    if m:
        target = m.group(1).strip()
        if target not in ('the', 'a', 'this', 'that', 'it'):
            ok, msg, _ = action_broker.execute_action('homie_launch_app', {'app_name': target}, caller_id=caller_id)
            if ok:
                return True, msg
            else:
                return True, f"⚠️ {msg}"

    # 7. Web Search query (e.g. "google <x>", "search for <x>")
    search_match = re.match(r'^(?:google|search\s+for|search|bing)\s+(.+)$', t)
    if search_match:
        query = search_match.group(1).strip()
        url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        webbrowser.open(url)
        return True, f"Searching the web for '{query}'"

    # 8. Time and Date
    if re.search(r'\b(what\s+time\s+is\s+it|current\s+time|the\s+time)\b', t):
        current_time = time.strftime("%I:%M %p").lstrip('0')
        return True, f"The time is {current_time}."
    if re.search(r'\b(what\s+is\s+today\'?s?\s+date|what\s+day\s+is\s+it|the\s+date)\b', t):
        current_date = time.strftime("%A, %B %d, %Y")
        return True, f"Today is {current_date}."

    # 9. Quick System Actions (lock PC)
    if re.search(r'\b(lock\s+computer|lock\s+screen|lock\s+pc|lock\s+my\s+pc|^lock$)\b', t):
        import ctypes
        ctypes.windll.user32.LockWorkStation()
        return True, "Workstation locked."

    # 21. Phone Gateway & Calling to PC ("start phone server", "phone status", "call my pc")
    if re.search(r'\b(start\s+(?:phone|call)\s+(?:server|gateway)|enable\s+phone\s+calls)\b', t):
        import phone_gateway
        ok, msg = phone_gateway.start_phone_gateway()
        return True, f"📞 {msg}"

    if re.search(r'\b(stop\s+(?:phone|call)\s+(?:server|gateway)|disable\s+phone\s+calls)\b', t):
        import phone_gateway
        ok, msg = phone_gateway.stop_phone_gateway()
        return True, f"📞 {msg}"

    if re.search(r'\b(phone\s+status|call\s+status|phone\s+gateway\s+status)\b', t):
        import phone_gateway
        conf = phone_gateway.load_phone_config()
        status_txt = "Online" if phone_gateway._server_instance else "Offline"
        return True, f"📞 **Phone Gateway**: {status_txt} on port {conf.get('port', 5055)}\n• Web Call Portal: `http://localhost:{conf.get('port', 5055)}/call`\n• Remote Touchpad: `http://localhost:{conf.get('port', 5055)}/remote`"

    # 22. Semantic Screen Memory Recall ("what was on my screen", "find on screen")
    screen_recall_m = re.match(r'^(?:what\s+was\s+on\s+my\s+screen(?:\s+(\d+)\s+minutes?\s+ago)?|screen\s+timeline)$', t)
    if screen_recall_m:
        import semantic_screen_memory
        mins = int(screen_recall_m.group(1)) if screen_recall_m.group(1) else 30
        summary = semantic_screen_memory.summarize_timeline_text(minutes=mins)
        return True, summary

    screen_find_m = re.match(r'^(?:find|search)\s+on\s+screen\s+(.+)$', t)
    if screen_find_m:
        import semantic_screen_memory
        q = screen_find_m.group(1).strip()
        hits = semantic_screen_memory.search_screen_history(q, limit=5)
        if not hits:
            return True, f"🔍 No occurrences of '{q}' found in screen history."
        lines = [f"🔍 Screen History matches for '{q}':"]
        for h in hits:
            lines.append(f"• [{h['time_str']}] `{h['proc_name']}` — {h['window_title']}")
        return True, "\n".join(lines)

    # 23. Claude Chrome Bridge ("ask claude", "send to claude", "claude status")
    claude_ask_m = re.match(r'^(?:ask\s+claude|send\s+to\s+claude)\s+(.+)$', t)
    if claude_ask_m:
        import claude_bridge
        q = claude_ask_m.group(1).strip()
        ok, msg = claude_bridge.send_message_to_claude(q)
        return True, f"🤖 Claude Bridge: {msg}"

    if re.search(r'\b(claude\s+status|claude\s+window)\b', t):
        import claude_bridge
        win = claude_bridge.find_claude_window()
        if win:
            return True, f"🤖 **Claude AI Chrome**: Detected! Title: `{win['title']}`, HWND: {win['hwnd']}"
        return True, "🤖 **Claude AI Chrome**: No active Claude AI window detected in Chrome."

    # 24. Pipeline Latency Telemetry & Observability
    if re.search(r'\b(latency\s+status|telemetry\s+report|pipeline\s+telemetry|speed\s+report)\b', t):
        import pipeline_telemetry
        rep = pipeline_telemetry.format_telemetry_report()
        return True, rep

    # 25. MCP Server Tools ("mcp status", "list mcp tools")
    if re.search(r'\b(mcp\s+status|list\s+mcp\s+tools|mcp\s+tools)\b', t):
        import homie_mcp
        tools = homie_mcp.MCP_TOOLS
        lines = [f"🔌 **Homie Workstation MCP Server** ({len(tools)} tools exposed):"]
        for tool in tools:
            lines.append(f"• `{tool['name']}`: {tool['description'][:65]}...")
        return True, "\n".join(lines)

    # 26. Voice Barge-in / Silence
    if re.search(r'^(?:shut\s+up|stop\s+talking|be\s+quiet|shh|silence)$', t):
        import voice
        voice.stop_speaking()
        return True, "Silenced."

    # 27. Cryptographic Agent Audit Ledger ("agent audit", "what did agents do")
    if re.search(r'\b(agent\s+audit|agent\s+ledger|what\s+did\s+agents\s+do|ai\s+activity)\b', t):
        import agent_audit_ledger
        rep = agent_audit_ledger.format_audit_report(limit=8)
        return True, rep

    # 28. Taint Tracking & Session Security
    if re.search(r'\b(taint\s+status|security\s+taint|taint\s+gate)\b', t):
        import taint_tracker
        st = taint_tracker.get_taint_status()
        taint_label = "🔴 TAINTED (Step-up approval active)" if st["is_tainted"] else "🟢 CLEAN"
        return True, f"🛡️ **Taint Security Gate**: {taint_label}\n• Source: `{st.get('source', 'None')}`\n• Pending Step-Up Approvals: {st['pending_step_ups']}"

    # 29. Desktop Agent Controls & Emergency Stop
    if re.search(r'^(?:emergency\s+stop|abort\s+agent|kill\s+agent)$', t):
        import desktop_agent
        desktop_agent.request_abort()
        return True, "🛑 Desktop Agent emergency abort signal triggered."

    return False, ""

# ----------------- Web Search & Read -----------------

def web_search(query, max_results=5):
    """Performs a free DuckDuckGo search without API keys."""
    try:
        url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            page = response.read().decode('utf-8', errors='ignore')

        out = []
        import html
        pattern = r'class="result__a" href="([^"]+)">(.*?)</a>.*?class="result__snippet"[^>]*>(.*?)</a>'
        for u, t, sn in re.findall(pattern, page, re.S)[:max_results]:
            actual_url = urllib.parse.parse_qs(urllib.parse.urlparse(html.unescape(u)).query).get('uddg', [u])[0]
            clean_t = re.sub(r'<[^>]+>', '', t).strip()
            clean_sn = re.sub(r'<[^>]+>', '', sn).strip()
            out.append(f"- {clean_t}: {actual_url}\n  {clean_sn}")

        return "\n\n".join(out) or "No search results found."
    except Exception as e:
        return f"Web search error: {e}"

def web_read(url):
    """Fetches a webpage and extracts clean, readable text."""
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            html = response.read().decode('utf-8', errors='ignore')

        # Drop script and style elements
        clean = re.sub(r'<(script|style|nav|footer|header)[^>]*>.*?</\1>', ' ', html, flags=re.DOTALL | re.I)
        # Drop HTML tags
        text = re.sub(r'<[^>]+>', ' ', clean)
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:4000]
    except Exception as e:
        return f"Failed to read webpage: {e}"

# ----------------- Safety Gate -----------------

DANGEROUS_COMMANDS = [
    r'\b(rmdir|rd)\s+/[sS]\b',
    r'\b(del|erase)\s+/[fFqQsS]\b',
    r'\bformat\s+[a-zA-Z]:',
    r'\b(shutdown|reboot)\b',
    r'\b(rm\s+-rf|rm\s+-fr)\b',
    r'\bdiskpart\b',
    r'\breg\s+delete\b',
]

def is_risky(command):
    """Checks if a command could cause data loss or system harm."""
    for pattern in DANGEROUS_COMMANDS:
        if re.search(pattern, command, re.I):
            return True
    return False

# ----------------- System Prompt for Claude Code -----------------

def build_system_prompt():
    rules = "\n".join(f"- {r}" for r in get_rules())
    monitors = windows_tools.get_monitors()
    mon_desc = "; ".join(f"{m['name']}: {m['width']}x{m['height']}" for m in monitors)
    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "None"

    me_path = os.path.abspath(__file__)
    prompt = f"""You are Homie, a fast, proactive Windows desktop AI assistant.
The user holds a hotkey, talks, and lets go. You answer questions and execute tasks on Windows.

Environment:
- Active Windows Displays: {mon_desc}
- Foreground Window: {fg_title}
- Persistent Rules:
{rules if rules else "- None"}

Guidelines:
1. Format output lines for the floating overlay:
   - "· note" for quick status or thought.
   - "▸ step" for concrete tool action in progress.
   - "✓ answer" for the final direct answer.
2. Directness:
   - Answer first. Keep answers to 1-3 short, clear sentences unless the user explicitly asks for detail.
   - Markdown and LaTeX math ($inline$, $$display$$) are fully supported.
3. Windows Tools Available (run via Bash/cmd):
   - Place windows: python "{me_path}" --place "<app>" <left|right|full|center>
   - View screen: python "{me_path}" --look
   - Web search: python "{me_path}" --search "<query>"
   - Read webpage: python "{me_path}" --read "<url>"
   - Media control: python "{me_path}" --media <play|pause|next|volup|voldown>
   - Remember rule: python "{me_path}" --remember "<rule>"
   - Read window text: python "{me_path}" --window "<app>"
4. Safety: Never run destructive commands (deletions, disk formatting, registry wipes) without explicit confirmation.
"""
    return prompt

# ----------------- Claude Code CLI Execution -----------------

def run_ai(task_text, step_callback=None):
    """
    Executes a task through the configured AI provider:
    - Google AI Studio (Gemini 2.0 / 1.5 Flash - 100% Free Tier)
    - NVIDIA NIM (Llama 3.3 70B, DeepSeek R1 - Free Developer APIs)
    - Groq Cloud (Free Tier)
    - Local Ollama
    - Claude Code CLI (if configured)
    """
    prefs = get_prefs()
    provider = prefs.get('provider', '').lower().strip()

    # If Claude CLI is explicitly requested and installed
    if provider == 'claude' and shutil.which('claude'):
        return run_claude(task_text, step_callback=step_callback)

    # Universal engine (Gemini, NVIDIA NIM, Groq, Ollama)
    import ai_engine
    return ai_engine.run_query(task_text, prefs, step_callback=step_callback)


def run_claude(task_text, step_callback=None):
    """Run Claude Code as a text-only provider for Homie's chat response.

    Local actions stay behind Homie's own command and tool routing. Claude Code
    must not receive unrestricted shell, file, or browser access from this path.
    """
    claude = shutil.which('claude')
    if not claude:
        return "Claude CLI is not installed or not in PATH. Please install Claude Code."

    prefs = get_prefs()
    model = prefs.get('model') or 'sonnet'
    # Homie's shared model preference may still contain a Gemini/OpenAI model
    # name. Claude Code accepts Claude aliases or model IDs only.
    if model not in {'haiku', 'sonnet', 'opus'} and not str(model).startswith('claude-'):
        model = 'sonnet'
    system_prompt = (
        "You are Homie, a concise Windows desktop assistant. Answer the user's "
        "request accurately and directly. You cannot operate the computer from "
        "this response provider; do not claim to have opened apps, changed files, "
        "sent messages, or performed other actions. Homie's local command router "
        "handles supported actions separately."
    )

    cmd = [
        claude,
        '-p',
        task_text,
        '--system-prompt', system_prompt,
        '--model', model,
        '--output-format', 'text',
        '--tools', ''
    ]

    env = os.environ.copy()
    if prefs.get('apiBase'):
        env['ANTHROPIC_BASE_URL'] = prefs['apiBase']
        if prefs.get('apiKey'):
            env['ANTHROPIC_AUTH_TOKEN'] = prefs['apiKey']

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=120,
            check=False
        )
        clean_text = re.sub(r'\x1b\[[0-9;]*[mGKF]', '', completed.stdout).strip()
        if completed.returncode != 0:
            detail = completed.stderr.strip() or clean_text or f'exit code {completed.returncode}'
            return f"Claude CLI failed: {detail}"
        if step_callback and clean_text:
            step_callback(f"✓ {clean_text}")
        return clean_text or "Claude returned an empty response."
    except subprocess.TimeoutExpired:
        return "Claude CLI timed out after 120 seconds."
    except Exception as e:
        return f"Error executing task: {e}"

# ----------------- Main Entrypoint -----------------

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd = args[0]

    if cmd in ('--pairing-unlock', 'pairing-unlock'):
        import phone_approval_portal
        # Interactive confirmation required to ensure automated background processes or agents cannot invoke it
        force = '--yes' in args or '-y' in args
        if not force:
            if sys.stdin.isatty():
                confirmation = input("Type 'CONFIRM-RESET' to unlock pairing: ").strip()
                if confirmation != "CONFIRM-RESET":
                    print("✗ [HOMIE SECURITY] Pairing unlock cancelled: confirmation code mismatch.")
                    return
            else:
                print("✗ [HOMIE SECURITY] Interactive console presence required to unlock pairing.")
                return
        ok, msg = phone_approval_portal.reset_pairing_lockout()
        print(f"✓ [HOMIE SECURITY] {msg}")
        return

    if cmd == '--look':
        files = windows_tools.capture_screens()
        for f in files:
            print(f)
        return

    if cmd == '--place':
        app = args[1] if len(args) > 1 else ""
        where = args[2] if len(args) > 2 else "full"
        ok, msg = windows_tools.place_window(app, where)
        print(msg)
        return

    if cmd == '--search':
        query = " ".join(args[1:])
        print(web_search(query))
        return

    if cmd == '--read':
        url = args[1] if len(args) > 1 else ""
        print(web_read(url))
        return

    if cmd == '--media':
        action = args[1] if len(args) > 1 else "play_pause"
        ok, msg = windows_tools.control_media(action)
        print(msg)
        return

    if cmd == '--window':
        app = args[1] if len(args) > 1 else ""
        print(windows_tools.read_window_text(app))
        return

    if cmd == '--fast':
        text = " ".join(args[1:])
        handled, msg = try_fast_command(text)
        if handled:
            print(f"✓ {msg}")
            sys.exit(0)
        else:
            sys.exit(1)

    if cmd == '--remember':
        rule = " ".join(args[1:])
        print(add_rule(rule))
        return

    if cmd == '--forget':
        words = " ".join(args[1:])
        print(remove_rule(words))
        return

    # Normal ask or query
    task = " ".join(args)
    # Check if it can run instantly with no AI
    handled, fast_msg = try_fast_command(task)
    if handled:
        print(f"✓ {fast_msg}")
        return

    # Otherwise send to AI (Google AI Studio, NVIDIA NIM, Groq, Ollama, Claude)
    result = run_ai(task, step_callback=lambda s: print(s, flush=True))
    print(result)

if __name__ == '__main__':
    main()
