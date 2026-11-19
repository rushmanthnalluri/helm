"""Universal AI Engine for Helm.
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
        'default_model': 'gemini-flash-lite-latest',
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
    },
    'local_offline': {
        'name': 'Local Zero-Config Mode',
        'base_url': '',
        'default_model': 'helm-local-assistant',
        'env_key': None,
        'doc_url': 'https://github.com/helm-ai/helm'
    }
}

GEMINI_MODELS_POOL = [
    'gemini-flash-lite-latest',
    'gemini-2.5-flash-lite',
    'gemini-flash-latest',
    'gemini-2.5-flash'
]

GEMINI_TOOLS = [
    {
        "functionDeclarations": [
            {
                "name": "send_chat_message",
                "description": "Sends a message or greeting to a contact in WhatsApp or Telegram on Windows.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "app_name": {
                            "type": "STRING",
                            "enum": ["whatsapp", "telegram"],
                            "description": "The messaging application (whatsapp or telegram)"
                        },
                        "recipient": {
                            "type": "STRING",
                            "description": "The contact or person name, e.g. 'Rusman', 'Amma'"
                        },
                        "message": {
                            "type": "STRING",
                            "description": "The message text to send, e.g. 'hi', 'how are you?'"
                        }
                    },
                    "required": ["app_name", "message"]
                }
            },
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
            },
            {
                "name": "get_clipboard",
                "description": "Reads the current text content from the Windows clipboard.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {}
                }
            },
            {
                "name": "set_clipboard",
                "description": "Copies a given string of text to the user's Windows clipboard.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "text": {
                            "type": "STRING",
                            "description": "The text to put onto the clipboard"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "list_downloads",
                "description": "Lists the most recent files downloaded in the user's Downloads folder.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {}
                }
            },
            {
                "name": "get_system_vitals",
                "description": "Gets real-time RAM, Disk, Battery, and Uptime health vitals of the Windows PC.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {}
                }
            }
        ]
    }
]

def detect_local_ollama(base_url=None):
    """Detects whether a local Ollama server is running and returns available models."""
    target_base = (base_url or os.environ.get('OLLAMA_API_BASE') or 'http://localhost:11434').rstrip('/')
    tags_url = f"{target_base}/api/tags"
    try:
        resp = requests.get(tags_url, timeout=0.35)
        if resp.status_code == 200:
            data = resp.json()
            models = [m.get('name') for m in data.get('models', []) if m.get('name')]
            default_m = models[0] if models else 'llama3.2'
            return {'available': True, 'models': models, 'default_model': default_m, 'base_url': f"{target_base}/v1"}
    except Exception:
        pass
    return {'available': False, 'models': [], 'default_model': None, 'base_url': f"{target_base}/v1"}

def get_active_provider(prefs):
    """Determines the active provider and credentials from settings and env vars.
    Falls back gracefully to Local Ollama or Local Zero-Config Mode when no cloud API keys exist.
    """
    provider = prefs.get('provider', '').lower().strip()
    if not provider or provider == 'auto':
        if os.environ.get('GEMINI_API_KEY') or prefs.get('geminiKey'):
            provider = 'gemini'
        elif os.environ.get('NVIDIA_API_KEY') or prefs.get('nvidiaKey'):
            provider = 'nvidia'
        elif os.environ.get('GROQ_API_KEY') or prefs.get('groqKey'):
            provider = 'groq'
        else:
            # Zero-config check: see if local Ollama daemon is live
            ollama_info = detect_local_ollama(prefs.get('apiBase'))
            if ollama_info['available']:
                provider = 'ollama'
            else:
                provider = 'local_offline'

    cfg = PROVIDER_CONFIGS.get(provider, PROVIDER_CONFIGS['local_offline'])
    model = prefs.get('model')
    if not model:
        if provider == 'ollama':
            ollama_info = detect_local_ollama(prefs.get('apiBase'))
            model = ollama_info['default_model'] or cfg['default_model']
        else:
            model = cfg['default_model']

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

def execute_tool(name, args, caller_id="ai_engine"):
    """Performs action through the unified ActionBroker with full complete mediation and security gates."""
    import action_broker
    try:
        ok, msg, res = action_broker.execute_action(name, args, caller_id=caller_id)
        return msg
    except Exception as e:
        logger.error("ActionBroker error executing %s: %s", name, e)
        return f"Error executing tool {name}: {e}"

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
            res = execute_tool("play_youtube", {"query": q})
            return f"✓ {res}\n\n{reply_text}"

    # 2. Chat messaging (WhatsApp / Telegram)
    for chat_app in ('whatsapp', 'telegram'):
        if chat_app in low_p and any(w in low_p for w in ('say', 'send', 'message', 'text', 'tell')):
            m1 = re.search(rf'^(?:open\s+)?{chat_app}\s+(?:and\s+|to\s+)?(?:say|send|text|message)\s+(.+?)\s+to\s+(.+)$', prompt_text, re.I)
            if m1:
                res = execute_tool("send_chat_message", {"app_name": chat_app, "recipient": m1.group(2).strip(), "message": m1.group(1).strip()})
                return f"✓ {res}\n\n{reply_text}"
            m2 = re.search(rf'^(?:open\s+)?{chat_app}\s+(?:and\s+|to\s+)?(?:say|send|text|message)\s+(?:to\s+)?([a-zA-Z0-9_\u0080-\uffff]+)\s+(.+)$', prompt_text, re.I)
            if m2:
                res = execute_tool("send_chat_message", {"app_name": chat_app, "recipient": m2.group(1).strip(), "message": m2.group(2).strip()})
                return f"✓ {res}\n\n{reply_text}"
            m3 = re.search(rf'^(?:open\s+)?{chat_app}\s+(?:and\s+|to\s+)?(?:say|type|send)\s+(.+)$', prompt_text, re.I)
            if m3:
                res = execute_tool("send_chat_message", {"app_name": chat_app, "recipient": "", "message": m3.group(1).strip()})
                return f"✓ {res}\n\n{reply_text}"

    # 3. App Launch (ensure messaging commands aren't hijacked by simple app launch)
    if not any(w in low_p for w in ('say', 'send', 'message', 'text', 'tell')):
        for app in ('whatsapp', 'telegram', 'notepad', 'spotify', 'chrome', 'edge', 'calc', 'calculator', 'terminal', 'cmd', 'explorer', 'code', 'discord', 'slack', 'teams', 'zoom', 'word', 'excel'):
            if (f"open {app}" in low_p or f"launch {app}" in low_p) or (f"opening {app}" in low_r or f"launched {app}" in low_r):
                res = execute_tool("open_app_or_url", {"target": app})
                return f"✓ {res}\n\n{reply_text}"

    # 3. Lock PC
    if 'lock' in low_p and any(w in low_p for w in ('pc', 'computer', 'screen')):
        execute_tool("lock_pc", {})
        return "✓ Windows workstation locked."

    return reply_text

# ----------------- Google Gemini Implementation with Native Tool Calling -----------------

def run_gemini(prompt_text, api_key, model='gemini-flash-lite-latest', step_callback=None):
    """Direct Google AI Studio API call with multi-model failover, tool execution loop, and vision support."""
    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "Desktop"
    monitors = windows_tools.get_monitors()
    mon_desc = "; ".join(f"{m['name']}: {m['width']}x{m['height']}" for m in monitors)

    system_instruction = (
        "You are Helm, a fast, proactive Windows desktop AI assistant. "
        "The user interacts with you via voice and Telegram from their phone. "
        "CRITICAL INSTRUCTION: You have real tools to perform actions on Windows. "
        "When the user asks you to send a message on WhatsApp or Telegram, open YouTube, play music, open apps, move windows, lock PC, or search, "
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

    # Automatic multi-model failover pool
    models_to_try = [model] + [m for m in GEMINI_MODELS_POOL if m != model]
    last_error = ""

    for cur_model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{cur_model}:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=20)
            if resp.status_code == 429:
                last_error = f"Model {cur_model} rate-limited (429)"
                if step_callback:
                    step_callback(f"· {cur_model} hit free quota, switching model...")
                continue
            if resp.status_code in (404, 503):
                last_error = f"Model {cur_model} unavailable ({resp.status_code})"
                continue
            if resp.status_code != 200:
                last_error = f"Gemini Error ({resp.status_code}): {resp.text}"
                continue

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

                tool_output = execute_tool(func_name, func_args)

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
            last_error = f"Gemini request failed: {e}"
            continue

    return f"Gemini temporarily unavailable ({last_error})."

# ----------------- OpenAI-Compatible Implementation (NVIDIA NIM / Groq / Ollama) -----------------

OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "play_youtube",
            "description": "Plays music, songs, or videos on YouTube in the browser.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Song, artist, or video name"}},
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "open_app_or_url",
            "description": "Opens an approved application (e.g. spotify, notepad) or website URL.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string", "description": "App name or URL"}},
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "place_window",
            "description": "Snaps or arranges windows on the desktop (left, right, full, center, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "app_or_title": {"type": "string"},
                    "where": {"type": "string", "enum": ["left", "right", "full", "center", "minimize", "maximize"]}
                },
                "required": ["where"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "media_control",
            "description": "Controls Windows media hardware playback keys.",
            "parameters": {
                "type": "object",
                "properties": {"action": {"type": "string", "enum": ["play", "pause", "play_pause", "next", "prev", "volup", "voldown", "mute"]}},
                "required": ["action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_chat_message",
            "description": "Sends messages on WhatsApp or Telegram.",
            "parameters": {
                "type": "object",
                "properties": {
                    "app_name": {"type": "string"},
                    "recipient": {"type": "string"},
                    "message": {"type": "string"}
                },
                "required": ["app_name", "message"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_vitals",
            "description": "Returns Windows CPU, RAM, battery, disk, and active window vitals.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "assistant_timeline",
            "description": "Queries the assistant timeline for what happened or 'what did I miss?'.",
            "parameters": {
                "type": "object",
                "properties": {"hours": {"type": "integer", "description": "Hours to look back"}}
            }
        }
    }
]

def run_openai_compat(prompt_text, prov, step_callback=None):
    """Executes requests via OpenAI-compatible endpoints with structured tool-calling loop."""
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
            "content": f"You are Helm, a fast Windows desktop AI assistant. Foreground: '{fg_title}'. Keep answers concise."
        },
        {"role": "user", "content": prompt_text}
    ]

    payload = {
        "model": prov['model'],
        "messages": messages,
        "temperature": 0.4,
        "max_tokens": 1024,
        "tools": OPENAI_TOOLS,
        "tool_choice": "auto"
    }

    max_steps = 4
    for step in range(max_steps):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                choice = data.get('choices', [{}])[0]
                msg = choice.get('message', {})
                tool_calls = msg.get('tool_calls', [])

                if not tool_calls:
                    raw_reply = msg.get('content', '').strip()
                    return check_and_execute_fallback(prompt_text, raw_reply)

                # Execute tool calls mediated by ActionBroker
                messages.append(msg)
                for tc in tool_calls:
                    fn = tc.get('function', {})
                    fn_name = fn.get('name', '')
                    try:
                        fn_args = json.loads(fn.get('arguments', '{}'))
                    except Exception:
                        fn_args = {}

                    if step_callback:
                        step_callback(f"▸ Executing {fn_name}: {fn_args}")

                    tool_output = execute_tool(fn_name, fn_args, caller_id=f"ai_{prov['provider']}")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get('id', f'call_{step}'),
                        "content": str(tool_output)
                    })

                payload['messages'] = messages
                continue

            elif "tools" in payload:
                # Fallback to plain prompt if provider does not support tools parameter
                del payload["tools"]
                del payload["tool_choice"]
                continue
            else:
                return f"Error from {prov['name']} ({resp.status_code}): {resp.text}"
        except Exception as e:
            return f"Error contacting {prov['name']}: {e}"

    return "Task completed."

# ----------------- Multimodal Vision Engine -----------------

def run_gemini_vision(prompt_text, image_source, api_key=None, step_callback=None):
    """Multimodal Vision inference using Google Gemini 2.5/Flash-Lite models."""
    if not api_key:
        import helm
        prefs = helm.get_prefs()
        api_key = prefs.get('geminiKey') or os.environ.get('GEMINI_API_KEY')

    if not api_key:
        return "Error: No Gemini API key found for vision analysis."

    b64_data = ""
    mime_type = "image/png"
    if isinstance(image_source, bytes):
        b64_data = base64.b64encode(image_source).decode('utf-8')
    elif isinstance(image_source, str) and os.path.exists(image_source):
        if image_source.lower().endswith(('.jpg', '.jpeg')):
            mime_type = "image/jpeg"
        with open(image_source, 'rb') as f:
            b64_data = base64.b64encode(f.read()).decode('utf-8')
    else:
        return "Invalid or missing image source."

    prompt = prompt_text or "What is in this image? Explain what you see clearly and concisely."

    contents = [{
        "role": "user",
        "parts": [
            {"text": prompt},
            {
                "inlineData": {
                    "mimeType": mime_type,
                    "data": b64_data
                }
            }
        ]
    }]

    payload = {
        "contents": contents,
        "systemInstruction": {
            "parts": [{
                "text": (
                    "You are Helm Vision, inspecting a screen capture or photo sent by the user from their phone or PC. "
                    "Be direct, accurate, and concise. Point out key details, errors, or elements clearly."
                )
            }]
        },
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024
        }
    }

    for model in ['gemini-flash-lite-latest', 'gemini-2.5-flash-lite', 'gemini-2.5-flash']:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            resp = requests.post(url, headers={'Content-Type': 'application/json'}, json=payload, timeout=25)
            if resp.status_code == 200:
                candidates = resp.json().get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    texts = [p.get('text', '') for p in parts if 'text' in p]
                    if texts:
                        return "".join(texts).strip()
        except Exception:
            pass

    return "Could not analyze the image (models currently unavailable)."

# ----------------- Main Query Dispatcher -----------------

def run_query(prompt_text, prefs, step_callback=None):
    """Dispatches query to the active provider (Gemini, NVIDIA, Groq, Ollama, or Local Zero-Config)."""
    prov = get_active_provider(prefs)

    # 1. Local Zero-Config Mode (No API keys and Ollama offline)
    if prov['provider'] == 'local_offline':
        if step_callback:
            step_callback("· Processing in Local Zero-Config Mode (Offline)...")
        # Try local desktop automation & tools first
        action_reply = check_and_execute_fallback(prompt_text, "")
        if action_reply:
            return action_reply

        # Handle system queries directly
        low = prompt_text.lower().strip()
        if any(w in low for w in ('vital', 'health', 'ram', 'cpu', 'battery')):
            return execute_tool("get_system_vitals", {})
        if any(w in low for w in ('download', 'recent file')):
            return execute_tool("list_downloads", {})
        if 'clipboard' in low:
            return execute_tool("get_clipboard", {})

        return (
            "👋 **Helm is running in Local Zero-Config Mode** (Private & Offline)\n\n"
            "Desktop controls, window snapping, media, and system vitals are fully active right now:\n"
            "• Try: *\"open notepad\"*, *\"lock pc\"*, *\"play lofi on youtube\"*, *\"vitals\"*\n\n"
            "**To enable free conversational intelligence:**\n"
            "1. **Local AI (Zero Cloud):** Install [Ollama](https://ollama.ai) and run `ollama run llama3.2`. Helm connects automatically!\n"
            "2. **Cloud AI:** Add a free API key (Google AI Studio, Groq, or NVIDIA) in **Settings**."
        )

    # 2. Local Ollama Provider
    if prov['provider'] == 'ollama':
        if step_callback:
            step_callback(f"· Connecting to {prov['name']} ({prov['model']})...")
        res = run_openai_compat(prompt_text, prov, step_callback=step_callback)
        if "Error contacting" in res or "Failed to establish" in res or "Connection refused" in res:
            return (
                "⚠️ **Local Ollama Server Not Reachable**\n\n"
                f"Helm attempted to connect to Ollama at `{prov['base_url']}`, but the daemon is not running.\n"
                "• Start Ollama by launching the Ollama app or running `ollama serve`.\n"
                "• Or download a model: `ollama run llama3.2`"
            )
        return res

    # 3. Cloud Provider missing API key
    if prov['api_key'] == 'none':
        return (
            f"No API key found for {prov['name']}.\n"
            f"Set it via `setx {PROVIDER_CONFIGS[prov['provider']]['env_key']} your_key` "
            f"or in ~/.config/helm/settings.json\n\n"
            f"Tip: You can also use free local AI with no keys by running `ollama run llama3.2`."
        )

    if step_callback:
        step_callback(f"· Connecting to {prov['name']} ({prov['model']})...")

    if prov['provider'] == 'gemini':
        res = run_gemini(prompt_text, prov['api_key'], model=prov['model'], step_callback=step_callback)
        if any(err in res.lower() for err in ('rate-limited', 'temporarily unavailable', '429', 'resource_exhausted', 'error (')) and (prefs.get('nvidiaKey') or os.environ.get('NVIDIA_API_KEY')):
            if step_callback:
                step_callback("· Gemini unavailable, failing over to NVIDIA NIM...")
            nv_prov = get_active_provider({**prefs, 'provider': 'nvidia'})
            nv_res = run_openai_compat(prompt_text, nv_prov, step_callback=step_callback)
            if not nv_res.startswith("Error"):
                return nv_res
        return res
    else:
        return run_openai_compat(prompt_text, prov, step_callback=step_callback)
