"""Universal AI Engine for Homie.
Supports Google AI Studio (Gemini), NVIDIA NIM, Groq, Ollama, and OpenAI-compatible APIs.
Provides direct multimodal vision and Windows desktop automation.
"""
import os
import sys
import json
import base64
import requests
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

PROVIDER_CONFIGS = {
    'gemini': {
        'name': 'Google AI Studio (Gemini)',
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
    """Executes a local Windows tool and returns the text result."""
    try:
        if name == "place_window":
            app = args.get('app_or_title', '')
            where = args.get('where', 'full')
            ok, msg = windows_tools.place_window(app, where)
            return msg
        elif name == "capture_screen":
            paths = windows_tools.capture_screens()
            return f"Screens captured: {', '.join(paths)}"
        elif name == "web_search":
            import homie
            return homie.web_search(args.get('query', ''))
        elif name == "media_control":
            ok, msg = windows_tools.control_media(args.get('action', 'play_pause'))
            return msg
        elif name == "launch_app":
            ok, msg = windows_tools.launch_app(args.get('name', ''))
            return msg
    except Exception as e:
        return f"Error executing tool {name}: {e}"
    return f"Unknown tool: {name}"

# ----------------- Google Gemini Implementation -----------------

def run_gemini(prompt_text, api_key, model='gemini-3.5-flash', step_callback=None):
    """Direct Google AI Studio API call with native multimodal image support."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}

    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "Desktop"
    monitors = windows_tools.get_monitors()
    mon_desc = "; ".join(f"{m['name']}: {m['width']}x{m['height']}" for m in monitors)

    system_instruction = (
        "You are Homie, a fast, helpful Windows desktop AI assistant. "
        "The user interacts with you via voice and Telegram. "
        "Answer directly, clearly and concisely (1-3 sentences unless asked for detail). "
        f"Active Windows foreground: '{fg_title}'. Monitors: {mon_desc}. "
        "If asked to move a window, search, or control media, state what action you are taking."
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

    payload = {
        "contents": [{"parts": parts}],
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 1024
        }
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=25)
        if resp.status_code == 200:
            data = resp.json()
            candidates = data.get('candidates', [])
            if candidates:
                content_parts = candidates[0].get('content', {}).get('parts', [])
                if content_parts:
                    return content_parts[0].get('text', '').strip()
            return "No response generated."
        else:
            return f"Gemini Error ({resp.status_code}): {resp.text}"
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
            return data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
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
