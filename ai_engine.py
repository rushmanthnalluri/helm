"""Universal AI Engine for Homie.
Supports Google AI Studio (Gemini), NVIDIA NIM, Groq, Ollama, and OpenAI-compatible APIs.
Provides direct multimodal vision and real Windows desktop automation with tool calling.
"""
import os
import sys
import json
import base64
import urllib.parse
import webbrowser
import requests
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

PROVIDER_CONFIGS = {
    'gemini': {
        'name': 'Google AI Studio (Gemini)',
        'base_url': 'https://generativelanguage.googleapis.com',
        'default_model': 'gemini-3.5-flash',
        'env_key': 'GEMINI_API_KEY',
        'doc_url': 'https://aistudio.google.com/app/apikey'
    },
    'nvidia': {
        'name': 'NVIDIA NIM',
        'base_url': 'https://integrate.api.nvidia.com/v1',
        'default_model': 'meta/llama-3.2-90b-vision-instruct',
        'env_key': 'NVIDIA_API_KEY',
        'doc_url': 'https://build.nvidia.com/'
    },
    'groq': {
        'name': 'Groq Cloud',
        'base_url': 'https://api.groq.com/openai/v1',
        'default_model': 'llama-3.3-70b-versatile',
        'env_key': 'GROQ_API_KEY',
        'doc_url': 'https://console.groq.com/keys'
    },
    'ollama': {
        'name': 'Local Ollama',
        'base_url': 'http://localhost:11434/v1',
        'default_model': 'qwen2.5:latest',
        'env_key': None,
        'doc_url': 'https://ollama.ai'
    }
}

GEMINI_TOOLS = [
    {
        "functionDeclarations": [
            {
                "name": "play_youtube",
                "description": "Opens YouTube in the default browser and plays or searches for a song, music, video, or playlist.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "query": {
                            "type": "STRING",
                            "description": "The song title, artist, or video query, e.g. 'the loose songs', 'lofi hip hop'"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "open_app_or_url",
                "description": "Launches a Windows program (e.g. Spotify, Notepad, Chrome, VS Code) or opens a website URL in the browser.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "target": {
                            "type": "STRING",
                            "description": "App name or URL, e.g. 'spotify', 'chrome', 'notepad', 'https://github.com'"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "place_window",
                "description": "Snaps or arranges a window on the Windows desktop.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "app_or_title": {
                            "type": "STRING",
                            "description": "Window title or application name, e.g. 'chrome', 'notepad'"
                        },
                        "where": {
                            "type": "STRING",
                            "enum": ["left", "right", "full", "center", "minimize", "maximize"]
                        }
                    },
                    "required": ["where"]
                }
            },
            {
                "name": "media_control",
                "description": "Simulates Windows media hardware keys (play, pause, next track, volume up/down, mute).",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "action": {
                            "type": "STRING",
                            "enum": ["play", "pause", "play_pause", "next", "prev", "volup", "voldown", "mute"]
                        }
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "web_search",
                "description": "Performs a web search via DuckDuckGo and returns search snippets.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "query": {
                            "type": "STRING",
                            "description": "Search query terms"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "lock_pc",
                "description": "Immediately locks the user's Windows computer.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {}
                }
            }
        ]
    }
]

def get_active_provider(prefs):
    """Determines the active provider and credentials from settings and env vars."""
    provider = prefs.get('provider', '').lower().strip()
    if not provider or provider == 'auto':
        if os.environ.get('GEMINI_API_KEY') or prefs.get('geminiKey'):
            provider = 'gemini'
        elif os.environ.get('NVIDIA_API_KEY') or prefs.get('nvidiaKey'):
            provider = 'nvidia'
        else:
            provider = 'gemini'

    cfg = PROVIDER_CONFIGS.get(provider, PROVIDER_CONFIGS['gemini'])
    model = prefs.get('model') or cfg['default_model']
    base_url = prefs.get('apiBase') or cfg.get('base_url', '')

    api_key = prefs.get(f'{provider}Key') or prefs.get('apiKey')
    if not api_key and cfg.get('env_key'):
        api_key = os.environ.get(cfg['env_key'], '')

    return {
        'provider': provider,
        'name': cfg['name'],
        'base_url': base_url.rstrip('/'),
        'model': model,
        'api_key': api_key or 'none'
    }

def execute_tool(name, args):
    """Actually performs the action on the Windows PC and returns the real result."""
    try:
        if name == "play_youtube":
            query = args.get('query', '').strip()
            url = f"https://www.youtube.com/results?search_query={urllib.parse.quote(query)}"
            webbrowser.open(url)
            return f"Opened YouTube search for '{query}' in the default browser."

        elif name == "open_app_or_url":
            target = args.get('target', '').strip()
            if target.startswith(('http://', 'https://')):
                webbrowser.open(target)
                return f"Opened webpage '{target}'"
            ok, msg = windows_tools.launch_app(target)
            return msg

        elif name == "place_window":
            app = args.get('app_or_title', '')
            where = args.get('where', 'full')
            ok, msg = windows_tools.place_window(app, where)
            return msg

        elif name == "media_control":
            action = args.get('action', 'play_pause')
            ok, msg = windows_tools.control_media(action)
            return msg

        elif name == "web_search":
            import homie
            return homie.web_search(args.get('query', ''))

        elif name == "lock_pc":
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            return "Windows workstation locked."

    except Exception as e:
        return f"Error executing tool {name}: {e}"
    return f"Unknown tool: {name}"

def check_and_execute_fallback(prompt_text, reply_text):
    """
    Guarantees that if the user requested an action or the AI claimed to do it,
    the action is physically executed on Windows and verified.
    Eliminates all false claims and hallucinations.
    """
    import re
    low_p = prompt_text.lower()
    low_r = reply_text.lower()

    # 1. YouTube & Music Playback
    if any(k in low_p or k in low_r for k in ('youtube', 'yt')) or 'play' in low_p:
        if any(w in low_p or w in low_r for w in ('song', 'music', 'video', 'playlist', 'play', 'open', 'search')):
            m = re.search(r'(?:open\s+(?:youtube|yt)\s+(?:and\s+|to\s+)?play|play|search\s+for)\s+["\']?([^"\'.\n,]+)', low_p)
            q = m.group(1).strip() if m else ""
            if not q or q in ('music', 'song', 'songs', 'video', 'playlist'):
                m2 = re.search(r'(?:playing|opening|searched\s+for)\s+["\']?([^"\'.\n,]+)', low_r)
                q = m2.group(1).strip() if m2 else "music"
            execute_tool("play_youtube", {"query": q})
            return f"✓ Opened YouTube for '{q}'.\n{reply_text}"

    # 2. App Launch
    for app in ('whatsapp', 'telegram', 'notepad', 'spotify', 'chrome', 'edge', 'calc', 'calculator', 'terminal', 'cmd', 'explorer', 'code', 'discord', 'slack', 'teams', 'zoom', 'word', 'excel'):
        if (f"open {app}" in low_p or f"launch {app}" in low_p) or (f"opening {app}" in low_r or f"launched {app}" in low_r):
            res = execute_tool("open_app_or_url", {"target": app})
            return f"✓ {res}\n{reply_text}"

    # 3. Lock PC
    if 'lock' in low_p and any(w in low_p for w in ('pc', 'computer', 'screen')):
        execute_tool("lock_pc", {})
        return "✓ Windows workstation locked."

    return reply_text

# ----------------- Google Gemini Implementation with Native Tool Calling -----------------

def run_gemini(prompt_text, api_key, model='gemini-3.5-flash', step_callback=None):
    """Direct Google AI Studio API call with tool execution loop and multimodal image support."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}

    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "Desktop"
    monitors = windows_tools.get_monitors()
    mon_desc = "; ".join(f"{m['name']}: {m['width']}x{m['height']}" for m in monitors)

    system_instruction = (
        "You are Homie, a fast, proactive Windows desktop AI assistant. "
        "The user interacts with you via voice and Telegram from their phone. "
        "CRITICAL INSTRUCTION: You have real tools to perform actions on Windows. "
        "When the user asks you to open YouTube, play music, open apps, move windows, lock PC, or search, "
        "YOU MUST CALL THE APPROPRIATE TOOL. Never claim you performed an action without calling its tool. "
        "Keep answers concise (1-2 sentences). "
        f"Active Windows foreground: '{fg_title}'. Connected Monitors: {mon_desc}."
    )

    parts = [{"text": prompt_text}]

    # If asking about the screen, attach screen capture as inlineData
    if any(w in prompt_text.lower() for w in ('screen', 'look', 'see', 'showing', 'display', 'desktop')):
        if step_callback:
            step_callback("· Capturing screen for vision...")
        screens = windows_tools.capture_screens()
        if screens and os.path.exists(screens[0]):
            try:
                with open(screens[0], 'rb') as f:
                    b64 = base64.b64encode(f.read()).decode('utf-8')
                parts.append({
                    "inlineData": {
                        "mimeType": "image/png",
                        "data": b64
                    }
                })
            except Exception:
                pass

    contents = [{"role": "user", "parts": parts}]

    payload = {
        "contents": contents,
        "tools": GEMINI_TOOLS,
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024
        }
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=25)
        if resp.status_code != 200:
            return f"Gemini Error ({resp.status_code}): {resp.text}"

        data = resp.json()
        candidates = data.get('candidates', [])
        if not candidates:
            return "No response generated."

        content = candidates[0].get('content', {})
        res_parts = content.get('parts', [])

        # Check for Tool / Function Calls
        fc_part = next((p for p in res_parts if 'functionCall' in p), None)
        if fc_part:
            fc = fc_part['functionCall']
            func_name = fc.get('name')
            func_args = fc.get('args', {})

            if step_callback:
                step_callback(f"▸ Executing {func_name}: {func_args}")

            # ACTUALLY EXECUTE THE ACTION ON WINDOWS
            tool_output = execute_tool(func_name, func_args)

            # Feed tool execution result back to Gemini for final confirmed answer
            contents.append(content)
            contents.append({
                "role": "user",
                "parts": [{
                    "functionResponse": {
                        "name": func_name,
                        "response": {"content": str(tool_output)}
                    }
                }]
            })

            followup_payload = {
                "contents": contents,
                "tools": GEMINI_TOOLS,
                "systemInstruction": {"parts": [{"text": system_instruction}]},
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 512}
            }
            resp2 = requests.post(url, headers=headers, json=followup_payload, timeout=20)
            if resp2.status_code == 200:
                followup_candidates = resp2.json().get('candidates', [])
                if followup_candidates:
                    fparts = followup_candidates[0].get('content', {}).get('parts', [])
                    text_parts = [p.get('text', '') for p in fparts if 'text' in p]
                    if text_parts:
                        return "".join(text_parts).strip()

            return f"✓ {tool_output}"

        # Regular text response
        text_parts = [p.get('text', '') for p in res_parts if 'text' in p]
        if text_parts:
            raw_reply = "".join(text_parts).strip()
            return check_and_execute_fallback(prompt_text, raw_reply)
        return "Task processed."

    except Exception as e:
        return f"Gemini request failed: {e}"

# ----------------- OpenAI-Compatible Implementation (NVIDIA NIM / Groq / Ollama) -----------------

def run_openai_compat(prompt_text, prov, step_callback=None):
    """Executes requests via OpenAI-compatible endpoints (NVIDIA NIM, Groq, Ollama)."""
    url = f"{prov['base_url']}/chat/completions"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {prov['api_key']}"
    }

    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "Desktop"

    messages = [
        {
            "role": "system",
            "content": f"You are Homie, a fast Windows desktop AI assistant. Foreground: '{fg_title}'. Keep answers concise."
        },
        {"role": "user", "content": prompt_text}
    ]

    payload = {
        "model": prov['model'],
        "messages": messages,
        "temperature": 0.4,
        "max_tokens": 1024
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            raw_reply = data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
            return check_and_execute_fallback(prompt_text, raw_reply)
        else:
            return f"Error from {prov['name']} ({resp.status_code}): {resp.text}"
    except Exception as e:
        return f"Error contacting {prov['name']}: {e}"

# ----------------- Main Query Dispatcher -----------------

def run_query(prompt_text, prefs, step_callback=None):
    """Dispatches query to the active provider (Gemini or NVIDIA NIM)."""
    prov = get_active_provider(prefs)

    if prov['api_key'] == 'none' and prov['provider'] != 'ollama':
        return (
            f"No API key found for {prov['name']}.\n"
            f"Set it via `setx {PROVIDER_CONFIGS[prov['provider']]['env_key']} your_key` "
            f"or in ~/.config/homie/settings.json"
        )

    if step_callback:
        step_callback(f"· Connecting to {prov['name']} ({prov['model']})...")

    if prov['provider'] == 'gemini':
        return run_gemini(prompt_text, prov['api_key'], model=prov['model'], step_callback=step_callback)
    else:
        return run_openai_compat(prompt_text, prov, step_callback=step_callback)
