"""Universal AI Engine for Homie.
Supports Google AI Studio (Gemini), NVIDIA NIM, Groq, Ollama, and OpenAI-compatible APIs.
Replaces the Claude requirement with 100% free cloud API tiers and local models.
"""
import os
import sys
import json
import base64
import requests
from pathlib import Path

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools

PROVIDER_CONFIGS = {
    'gemini': {
        'name': 'Google AI Studio (Gemini)',
        'base_url': 'https://generativelanguage.googleapis.com/v1beta/openai/',
        'default_model': 'gemini-2.0-flash',
        'env_key': 'GEMINI_API_KEY',
        'doc_url': 'https://aistudio.google.com/app/apikey'
    },
    'nvidia': {
        'name': 'NVIDIA NIM',
        'base_url': 'https://integrate.api.nvidia.com/v1',
        'default_model': 'meta/llama-3.3-70b-instruct',
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

TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "place_window",
            "description": "Snaps or moves a window on Windows desktop.",
            "parameters": {
                "type": "object",
                "properties": {
                    "app_or_title": {"type": "string", "description": "Application name or title, e.g. 'chrome', 'notepad'"},
                    "where": {"type": "string", "enum": ["left", "right", "full", "center", "minimize", "maximize"]}
                },
                "required": ["where"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "capture_screen",
            "description": "Captures a screenshot of the user's displays for inspection.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Searches the web using DuckDuckGo.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search keywords"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "media_control",
            "description": "Controls audio playback (play, pause, next track, volume up/down, mute).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["play", "pause", "next", "prev", "volup", "voldown", "mute"]}
                },
                "required": ["action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "launch_app",
            "description": "Launches a Windows program or opens a file/URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "App or website name, e.g. 'calc', 'notepad', 'spotify'"}
                },
                "required": ["name"]
            }
        }
    }
]

def get_active_provider(prefs):
    """Determines the active provider and credentials from settings and env vars."""
    provider = prefs.get('provider', '').lower().strip()
    
    # Auto-detect if not explicitly configured
    if not provider or provider == 'auto':
        if os.environ.get('GEMINI_API_KEY') or prefs.get('geminiKey'):
            provider = 'gemini'
        elif os.environ.get('NVIDIA_API_KEY') or prefs.get('nvidiaKey'):
            provider = 'nvidia'
        elif os.environ.get('GROQ_API_KEY') or prefs.get('groqKey'):
            provider = 'groq'
        else:
            # Fall back to gemini or nvidia
            provider = 'gemini'

    cfg = PROVIDER_CONFIGS.get(provider, PROVIDER_CONFIGS['gemini'])
    base_url = prefs.get('apiBase') or cfg['base_url']
    model = prefs.get('model') or cfg['default_model']
    
    api_key = prefs.get(f'{provider}Key') or prefs.get('apiKey')
    if not api_key and cfg['env_key']:
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

def run_query(prompt_text, prefs, step_callback=None):
    """
    Runs a query through Google AI Studio (Gemini), NVIDIA NIM, Groq, or Ollama.
    Streams progress steps and handles tool use automatically.
    """
    prov = get_active_provider(prefs)

    if prov['api_key'] == 'none' and prov['provider'] != 'ollama':
        return (
            f"No API key found for {prov['name']}.\n"
            f"Get a free API key at:\n"
            f"- Google AI Studio: https://aistudio.google.com/app/apikey\n"
            f"- NVIDIA NIM: https://build.nvidia.com/\n\n"
            f"Set it via `setx {PROVIDER_CONFIGS[prov['provider']]['env_key']} your_key` "
            f"or in ~/.config/homie/settings.json"
        )

    url = f"{prov['base_url']}/chat/completions"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {prov['api_key']}"
    }

    # Context about active windows and rules
    fg = windows_tools.get_foreground_window()
    fg_title = fg['title'] if fg else "Desktop"
    monitors = windows_tools.get_monitors()
    mon_desc = "; ".join(f"{m['name']}: {m['width']}x{m['height']}" for m in monitors)

    system_content = f"""You are Homie, a fast, proactive Windows desktop AI assistant.
The user speaks to you via a hold-to-talk voice shortcut. You answer questions and take actions on their Windows PC.

Active Windows Environment:
- Foreground Window: {fg_title}
- Monitors: {mon_desc}

Style:
- Answer directly and concisely (1-3 sentences unless asked for detail).
- Prefix thinking notes with '· ' and actions with '▸ '.
- Markdown is supported.
- Use provided tools when the user asks to move windows, take a screenshot, search the web, control media, or launch apps.
"""

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": prompt_text}
    ]

    # If the user is asking about the screen, attach screen capture automatically
    if any(w in prompt_text.lower() for w in ('screen', 'look', 'see', 'showing', 'display')):
        if step_callback:
            step_callback("· Capturing screen for inspection...")
        screens = windows_tools.capture_screens()
        if screens and os.path.exists(screens[0]):
            try:
                with open(screens[0], 'rb') as img_f:
                    b64_img = base64.b64encode(img_f.read()).decode('utf-8')
                # Add image to user message for vision models
                messages[-1]["content"] = [
                    {"type": "text", "text": prompt_text},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/png;base64,{b64_img}"}
                    }
                ]
            except Exception:
                pass

    if step_callback:
        step_callback(f"· Connecting to {prov['name']} ({prov['model']})...")

    payload = {
        "model": prov['model'],
        "messages": messages,
        "tools": TOOLS_SPEC,
        "tool_choice": "auto",
        "temperature": 0.4,
        "max_tokens": 1024
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code != 200:
            return f"API Error from {prov['name']} ({resp.status_code}): {resp.text}"

        data = resp.json()
        choice = data.get('choices', [{}])[0]
        msg = choice.get('message', {})

        # Handle Tool Calls
        tool_calls = msg.get('tool_calls', [])
        if tool_calls:
            # Append assistant message with tool calls
            messages.append(msg)
            for tc in tool_calls:
                func_name = tc.get('function', {}).get('name')
                raw_args = tc.get('function', {}).get('arguments', '{}')
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    args = {}

                if step_callback:
                    step_callback(f"▸ Running {func_name}: {args}")

                tool_result = execute_tool(func_name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get('id', 'call_1'),
                    "content": str(tool_result)
                })

            # Follow up call to get final synthesized response
            follow_payload = {
                "model": prov['model'],
                "messages": messages,
                "temperature": 0.4,
                "max_tokens": 1024
            }
            resp2 = requests.post(url, headers=headers, json=follow_payload, timeout=30)
            if resp2.status_code == 200:
                final_msg = resp2.json().get('choices', [{}])[0].get('message', {}).get('content', '')
                return final_msg.strip() if final_msg else "Done."

        content = msg.get('content', '').strip()
        return content if content else "Task finished."

    except Exception as e:
        return f"Error contacting {prov['name']}: {e}"
