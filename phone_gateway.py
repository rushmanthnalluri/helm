"""Homie Phone Gateway.
Provides interactive telephone voice calling to your Windows PC via:
1. Twilio Voice PSTN Webhook: Call your PC from any standard mobile phone or landline.
2. Mobile Duplex Web Audio Portal (/call): Call your PC from any smartphone browser over Wi-Fi/LAN without Twilio fees.
3. Outbound Telephone Alerts: Homie can dial your phone when critical alerts or timers trigger.
"""

import os
import sys
import json
import time
import logging
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import db_utils

logger = logging.getLogger("homie.phone_gateway")

# Default gateway configuration
DEFAULT_PHONE_CONFIG = {
    "enabled": True,
    "host": "127.0.0.1", # Bound to loopback by default
    "port": 5055,
    "pin": "",            # Cryptographically generated on first setup
    "require_pin": True,
    "allowed_numbers": [],
    "twilio_account_sid": "",
    "twilio_auth_token": "",
    "twilio_phone_number": "",
    "user_phone_number": "",
    "voice_greeting": "Homie workstation online. How can I assist you?",
    "voice_name": "Polly.Danielle"
}

def validate_twilio_signature(url: str, params: dict, signature: str, auth_token: str) -> bool:
    """Validates X-Twilio-Signature header using HMAC-SHA1 according to Twilio webhook specs."""
    if not auth_token or not signature:
        return False
    import hmac, hashlib, base64
    data = url
    for k in sorted(params.keys()):
        val = params[k]
        data += f"{k}{val if isinstance(val, str) else val[0]}"
    expected_sig = base64.b64encode(
        hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).digest()
    ).decode("utf-8")
    return hmac.compare_digest(expected_sig, signature)

_server_instance = None
_server_thread = None
_call_state = {}

_SEEN_PHONE_NONCES = set()

MAX_AUDIO_PAYLOAD_BYTES = 5 * 1024 * 1024   # 5 MB

MAX_AUDIO_DURATION_SECS = 30.0             # 30 seconds
_DEVICE_NONCES = {}  # device_token:nonce -> expiry_timestamp
_SHARED_VOICE_ENGINE = None

def get_shared_voice_engine():
    global _SHARED_VOICE_ENGINE
    if _SHARED_VOICE_ENGINE is None:
        import voice
        _SHARED_VOICE_ENGINE = voice.VoiceEngine()
    return _SHARED_VOICE_ENGINE

import secrets
import qrcode
import io
import base64
import socket

def init_device_pairing_db():
    with db_utils.get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS paired_mobile_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                device_name TEXT,
                paired_at REAL NOT NULL,
                last_used REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_pairing_codes (
                code TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        conn.commit()

init_device_pairing_db()

def create_mobile_pairing_code(valid_seconds=900):
    """Generates a secure 6-character short code and full session token."""
    code = secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") + "".join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(5))
    token = secrets.token_hex(24)
    expires = time.time() + valid_seconds

    with db_utils.get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO pending_pairing_codes (code, token, expires_at) VALUES (?, ?, ?)", (code, token, expires))
        conn.commit()
    return code, token

def exchange_pairing_code_for_token(code, device_name="Mobile Device"):
    """Validates short code and returns permanent device token."""
    clean_code = (code or "").strip().upper()
    now = time.time()

    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT token, expires_at FROM pending_pairing_codes WHERE code = ?", (clean_code,))
        row = cur.fetchone()
        if not row:
            return None, "Invalid pairing code."
        token, expires = row[0], row[1]
        if now > expires:
            conn.execute("DELETE FROM pending_pairing_codes WHERE code = ?", (clean_code,))
            conn.commit()
            return None, "Pairing code has expired."

        # Register permanent device token
        conn.execute("DELETE FROM pending_pairing_codes WHERE code = ?", (clean_code,))
        conn.execute("INSERT OR REPLACE INTO paired_mobile_devices (token, device_name, paired_at, last_used) VALUES (?, ?, ?, ?)",
                     (token, device_name, now, now))
        conn.commit()
    return token, "Device paired successfully."

def is_device_token_valid(token):
    if not token:
        return False
    with db_utils.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM paired_mobile_devices WHERE token = ?", (str(token).strip(),))
        row = cur.fetchone()
        if row:
            conn.execute("UPDATE paired_mobile_devices SET last_used = ? WHERE token = ?", (time.time(), str(token).strip()))
            conn.commit()
            return True
    return False

def generate_qr_base64(url):
    """Generates a PNG QR code in base64 format for rendering in HTML."""
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def get_phone_config_path():
    cfg_dir = Path.home() / ".config" / "homie"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "phone_config.json"

def load_phone_config():
    path = get_phone_config_path()
    conf = DEFAULT_PHONE_CONFIG.copy()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
                conf.update(saved)
        except Exception as e:
            logger.error("Failed to load phone config: %s", e)
    
    # Ensure PIN is not default 1234 or empty
    if not conf.get("pin") or conf.get("pin") == "1234":
        conf["pin"] = secrets.token_hex(3).upper() # 6 hex chars
        save_phone_config(conf)
        logger.info("Generated fresh cryptographically secure phone PIN.")
    return conf

def save_phone_config(conf):
    path = get_phone_config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2)
        return True
    except Exception as e:
        logger.error("Failed to save phone config: %s", e)
        return False

def execute_phone_instruction(speech_text, session_id="call"):
    """Executes spoken instruction from a phone call on the local Windows PC."""
    speech = (speech_text or "").strip()
    if not speech:
        return "I didn't hear anything. Could you please repeat?"

    logger.info("Executing phone instruction: %s", speech)

    # 1. Try instant fast-command first (<50ms)
    try:
        import homie
        handled, msg = homie.try_fast_command(speech, caller_id="phone_gateway")
        if handled:
            # Clean up message for voice output (short & clear)
            clean_msg = msg.replace("\n", ". ").replace("`", "")
            return clean_msg
    except Exception as e:
        logger.warning("Fast command check failed: %s", e)

    # 2. Try AI Engine tool execution through shared broker
    try:
        import ai_engine
        import homie
        prefs = homie.get_prefs()
        
        system_prompt = (
            "You are Homie, speaking over a live telephone call to your user about their Windows PC. "
            "Keep replies brief, conversational, and helpful (1-3 sentences). "
            "Do not output markdown, bullet points, asterisks, or code blocks, as this is read over a phone call."
        )
        reply = ai_engine.run_query(
            prompt_text=f"{system_prompt}\nUser says: {speech}",
            prefs=prefs
        )
        if reply:
            return reply.strip()
    except Exception as e:
        logger.error("AI execution failed: %s", e)

    return f"I received: {speech}, but could not complete the operation."

def _get_call_page_html() -> str:
    conf = load_phone_config()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Homie Phone Call</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: #0d1117; color: #e6edf3; display: flex; flex-direction: column; height: 100vh; overflow: hidden; justify-content: space-between; align-items: center; padding: 24px; }}
  .header {{ text-align: center; margin-top: 16px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; color: #58a6ff; letter-spacing: -0.5px; }}
  .header p {{ font-size: 14px; color: #8b949e; margin-top: 4px; }}
  .status-badge {{ display: inline-flex; align-items: center; gap: 6px; background: rgba(56, 139, 253, 0.15); color: #58a6ff; border: 1px solid rgba(56, 139, 253, 0.3); border-radius: 20px; padding: 4px 12px; font-size: 12px; margin-top: 12px; }}
  .status-dot {{ width: 8px; height: 8px; border-radius: 50%; background: #3fb950; animation: pulse 2s infinite; }}
  @keyframes pulse {{ 0% {{ opacity: 0.4; transform: scale(0.9); }} 50% {{ opacity: 1; transform: scale(1.1); }} 100% {{ opacity: 0.4; transform: scale(0.9); }} }}
  
  .transcript-box {{ width: 100%; max-width: 440px; flex: 1; margin: 24px 0; background: rgba(22, 27, 34, 0.8); border: 1px solid #30363d; border-radius: 16px; padding: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; }}
  .bubble {{ max-width: 85%; padding: 10px 14px; border-radius: 14px; font-size: 14px; line-height: 1.4; }}
  .bubble.user {{ align-self: flex-end; background: #1f6feb; color: #fff; }}
  .bubble.assistant {{ align-self: flex-start; background: #21262d; border: 1px solid #30363d; color: #c9d1d9; }}
  
  .call-controls {{ width: 100%; max-width: 440px; display: flex; flex-direction: column; align-items: center; gap: 16px; margin-bottom: 24px; }}
  .btn-call {{ width: 84px; height: 84px; border-radius: 50%; background: #238636; border: none; color: white; display: flex; justify-content: center; align-items: center; cursor: pointer; transition: all 0.2s; box-shadow: 0 0 24px rgba(35, 134, 54, 0.4); }}
  .btn-call:active {{ transform: scale(0.92); }}
  .btn-call.in-call {{ background: #da3633; box-shadow: 0 0 24px rgba(218, 54, 51, 0.5); }}
  .btn-call svg {{ width: 36px; height: 36px; fill: currentColor; }}
  
  .quick-links {{ display: flex; gap: 16px; }}
  .quick-links a {{ color: #8b949e; text-decoration: none; font-size: 13px; }}
  .quick-links a:hover {{ color: #58a6ff; }}
</style>
</head>
<body>
  <div class="header">
    <h1>🏠 Homie Voice Call</h1>
    <p>Live audio connection to your Windows PC</p>
    <div class="status-badge"><span class="status-dot"></span> PC Connected</div>
  </div>

  <div class="transcript-box" id="transcript">
    <div class="bubble assistant">Workstation ready. Tap the call button and say anything to your PC.</div>
  </div>

  <div class="call-controls">
    <button class="btn-call" id="callBtn" onclick="toggleCall()">
      <svg id="callIcon" viewBox="0 0 24 24"><path d="M6.62 10.79a15.053 15.053 0 006.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/></svg>
    </button>
    <div style="font-size: 13px; color: #8b949e;" id="callStatus">Tap to Start Voice Call</div>
  </div>

  <div class="quick-links">
    <a href="/remote">📱 Remote Touchpad</a>
    <a href="/status">⚡ PC Vitals</a>
  </div>

<script>
let inCall = false;
let recognition = null;
const transcript = document.getElementById('transcript');
const callBtn = document.getElementById('callBtn');
const callStatus = document.getElementById('callStatus');

function addBubble(text, role) {{
  const b = document.createElement('div');
  b.className = 'bubble ' + role;
  b.textContent = text;
  transcript.appendChild(b);
  transcript.scrollTop = transcript.scrollHeight;
}}

function playAudioB64(b64, fallbackText) {{
  try {{
    const audio = new Audio("data:audio/wav;base64," + b64);
    audio.play();
    return true;
  }} catch(e) {{
    if (fallbackText) speakTTS(fallbackText);
    return false;
  }}
}}

function speakTTS(text) {{
  if ('speechSynthesis' in window) {{
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.rate = 1.0;
    u.pitch = 1.0;
    window.speechSynthesis.speak(u);
  }}
}}

let mediaRecorder = null;
let audioChunks = [];

function initMediaRecorder() {{
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {{
    alert("Microphone access is not available in this browser.");
    return false;
  }}
  navigator.mediaDevices.getUserMedia({{ audio: true }}).then(stream => {{
    mediaRecorder = new MediaRecorder(stream);
    audioChunks = [];
    mediaRecorder.ondataavailable = e => {{ if (e.data.size > 0) audioChunks.push(e.data); }};
    mediaRecorder.onstop = async () => {{
      const blob = new Blob(audioChunks, {{ type: 'audio/wav' }});
      callStatus.textContent = 'Transcribing with local Whisper...';
      const reader = new FileReader();
      reader.readAsDataURL(blob);
      reader.onloadend = async () => {{
        const b64 = reader.result.split(',')[1];
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token') || sessionStorage.getItem('homie_token') || '';
        try {{
          const resp = await fetch('/api/audio-call', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ audio_b64: b64, token: token }})
          }});
          const data = await resp.json();
          if (data.transcription) addBubble(data.transcription, 'user');
          if (data.reply) {{
            addBubble(data.reply, 'assistant');
            if (data.audio_b64) playAudioB64(data.audio_b64, data.reply);
            else speakTTS(data.reply);
          }}
        }} catch(err) {{
          addBubble("Audio gateway network error.", 'assistant');
        }} finally {{
          callStatus.textContent = 'Listening... Speak anytime';
          if (inCall && mediaRecorder.state === 'inactive') {{
            audioChunks = [];
            mediaRecorder.start();
          }}
        }}
      }};
    }};
    if (inCall) mediaRecorder.start();
  }}).catch(err => {{
    console.error("Mic error:", err);
  }});
  return true;
}}

function initSpeech() {{
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {{
    // Fall back to MediaRecorder with server-side local Whisper STT
    return initMediaRecorder();
  }}
  recognition = new SpeechRec();
  recognition.continuous = true;
  recognition.interimResults = false;
  recognition.lang = 'en-US';

  recognition.onresult = async (event) => {{
    const lastResult = event.results[event.results.length - 1];
    if (lastResult.isFinal) {{
      const userText = lastResult[0].transcript.trim();
      if (!userText) return;
      addBubble(userText, 'user');
      callStatus.textContent = 'Processing with Homie...';
      
      try {{
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token') || sessionStorage.getItem('homie_token') || '';
        const resp = await fetch('/api/web-call', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ speech: userText, token: token }})
        }});
        const data = await resp.json();
        addBubble(data.reply, 'assistant');
        if (data.audio_b64) {{
          playAudioB64(data.audio_b64, data.reply);
        }} else {{
          speakTTS(data.reply);
        }}
      }} catch (err) {{
        addBubble("Network error communicating with PC.", 'assistant');
      }} finally {{
        callStatus.textContent = 'Listening... Speak anytime';
      }}
    }}
  }};

  recognition.onerror = (e) => {{
    console.error('Speech error', e);
  }};

  recognition.onend = () => {{
    if (inCall) {{
      try {{ recognition.start(); }} catch(e) {{}}
    }}
  }};
  return true;
}}

function toggleCall() {{
  if (!inCall) {{
    if (!recognition && !initSpeech()) return;
    try {{
      recognition.start();
      inCall = true;
      callBtn.classList.add('in-call');
      callStatus.textContent = 'Listening... Speak anytime';
      speakTTS("Homie online. I am listening.");
    }} catch(e) {{
      console.error(e);
    }}
  }} else {{
    inCall = false;
    if (recognition) recognition.stop();
    callBtn.classList.remove('in-call');
    callStatus.textContent = 'Call Ended. Tap to restart.';
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  }}
}}
</script>
</body>
</html>"""


def _get_signing_portal_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'">
<title>Homie Hardware Approval Portal</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: #090d16; color: #e6edf3; min-height: 100vh; padding: 16px; display: flex; flex-direction: column; align-items: center; }
  .card { width: 100%; max-width: 480px; background: #161b22; border: 1px solid #30363d; border-radius: 16px; padding: 20px; margin-bottom: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
  h1 { font-size: 20px; color: #58a6ff; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
  p.sub { font-size: 13px; color: #8b949e; margin-bottom: 16px; }
  .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge-warn { background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }
  .badge-ok { background: rgba(63, 185, 80, 0.15); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }
  .field { margin: 10px 0; }
  .field label { display: block; font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
  .field .val { font-size: 14px; color: #f0f6fc; font-weight: 500; word-break: break-all; }
  pre.args { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 12px; font-size: 12px; color: #79c0ff; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, monospace; max-height: 200px; }
  .btn-group { display: flex; gap: 12px; margin-top: 20px; }
  button { flex: 1; padding: 12px; border-radius: 10px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
  .btn-approve { background: #238636; color: white; }
  .btn-approve:active { background: #2ea043; transform: scale(0.98); }
  .btn-deny { background: #21262d; color: #f85149; border: 1px solid #30363d; }
  .btn-deny:active { background: #30363d; transform: scale(0.98); }
  input[type="text"] { width: 100%; padding: 10px 14px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: white; font-size: 14px; margin-top: 4px; }
  .hash-preview { font-family: ui-monospace, monospace; font-size: 10px; color: #8b949e; word-break: break-all; background: #0d1117; padding: 6px 8px; border-radius: 6px; margin-top: 4px; }
</style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Homie Phone Authenticator</h1>
    <p class="sub">Hardware-Grounded RFC 8032 Ed25519 Cryptographic Approval Portal</p>
    <div class="field">
      <label>Device ID</label>
      <input type="text" id="dev-id" value="primary_phone" onchange="refreshChallenges()">
    </div>
    <div class="field" style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <label>Monotonic Counter</label>
        <span class="val" id="counter-val">1</span>
      </div>
      <div>
        <span class="badge badge-ok" id="status-badge">● Ready to Sign</span>
      </div>
    </div>
  </div>

  <div id="challenges-container" style="width: 100%; max-width: 480px;"></div>

  <div class="card" id="empty-state" style="text-align: center; padding: 36px 20px;">
    <div style="font-size: 32px; margin-bottom: 12px;">✅</div>
    <h3 style="color: #f0f6fc; margin-bottom: 6px;">Zero Pending Authorizations</h3>
    <p style="color: #8b949e; font-size: 13px;">Your workstation is safe. Sensitive high-tier actions will appear here for cryptographic signature approval.</p>
  </div>

<script>
let clientCounter = parseInt(localStorage.getItem('homie_signing_counter') || '1');
document.getElementById('counter-val').textContent = clientCounter;

function getDeviceId() {
  return document.getElementById('dev-id').value.trim() || 'primary_phone';
}

async function refreshChallenges() {
  const devId = getDeviceId();
  try {
    const res = await fetch('/api/pending-challenges?device_id=' + encodeURIComponent(devId));
    if (!res.ok) return;
    const data = await res.json();
    renderChallenges(data.challenges || []);
  } catch(e) {
    console.warn("Poll challenges error:", e);
  }
}

function renderChallenges(challenges) {
  const container = document.getElementById('challenges-container');
  const emptyState = document.getElementById('empty-state');
  container.innerHTML = '';

  if (!challenges || challenges.length === 0) {
    emptyState.style.display = 'block';
    return;
  }
  emptyState.style.display = 'none';

  challenges.forEach(ch => {
    const card = document.createElement('div');
    card.className = 'card';
    card.id = 'ch-' + ch.step_up_id;

    const remainingSecs = Math.max(0, ch.expiry - Math.floor(Date.now() / 1000));
    const canonicalText = ch.canonical_args;
    if (!canonicalText) {
      console.error("Malformed challenge: missing canonical_args", ch);
      return;
    }

    const headerDiv = document.createElement('div');
    headerDiv.style.cssText = 'display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;';
    headerDiv.innerHTML = '<span class="badge badge-warn">⚠️ Step-Up Authorization</span><span style="font-size:12px; color:#f85149;">Expires in ' + remainingSecs + 's</span>';
    card.appendChild(headerDiv);

    const toolField = document.createElement('div');
    toolField.className = 'field';
    toolField.innerHTML = '<label>Action / Tool</label>';
    const toolVal = document.createElement('div');
    toolVal.className = 'val';
    toolVal.style.cssText = 'color:#58a6ff; font-weight:700;';
    toolVal.textContent = ch.tool_name;
    toolField.appendChild(toolVal);
    card.appendChild(toolField);

    const argsField = document.createElement('div');
    argsField.className = 'field';
    argsField.innerHTML = '<label>Target Arguments (What You See Is What You Sign)</label>';
    const pre = document.createElement('pre');
    pre.className = 'args';
    pre.textContent = canonicalText; // STRICT TEXTCONTENT RENDERING PREVENTS HTML/XSS INJECTION
    argsField.appendChild(pre);

    const sizeNotice = document.createElement('div');
    sizeNotice.style.cssText = 'font-size:10px; color:#8b949e; margin-top:2px;';
    sizeNotice.textContent = 'Payload Size: ' + canonicalText.length + ' bytes | Hash Verified';
    argsField.appendChild(sizeNotice);
    card.appendChild(argsField);

    const metaField = document.createElement('div');
    metaField.className = 'field';
    metaField.innerHTML = '<label>Session & Seq Binding</label>';
    const metaVal = document.createElement('div');
    metaVal.className = 'val';
    metaVal.style.cssText = 'font-size:12px; color:#8b949e;';
    metaVal.textContent = 'Session: ' + ch.session_id + ' | Seq: ' + ch.challenge_seq + ' | Epoch: ' + ch.taint_epoch;
    metaField.appendChild(metaVal);
    card.appendChild(metaField);

    const hashField = document.createElement('div');
    hashField.className = 'field';
    hashField.innerHTML = '<label>Cryptographic Challenge Hash</label>';
    const hashVal = document.createElement('div');
    hashVal.className = 'hash-preview';
    hashVal.textContent = ch.challenge_hash;
    hashField.appendChild(hashVal);
    card.appendChild(hashField);

    const btnGroup = document.createElement('div');
    btnGroup.className = 'btn-group';

    const denyBtn = document.createElement('button');
    denyBtn.className = 'btn-deny';
    denyBtn.textContent = 'Deny';
    denyBtn.onclick = () => denyChallenge(ch.step_up_id);
    btnGroup.appendChild(denyBtn);

    const approveBtn = document.createElement('button');
    approveBtn.className = 'btn-approve';
    approveBtn.textContent = 'Approve & Sign (WebCrypto P-256)';
    approveBtn.onclick = () => signAndApprove(ch, canonicalText.length);
    btnGroup.appendChild(approveBtn);

    card.appendChild(btnGroup);
    container.appendChild(card);
  });
}

// -------------------------------------------------------------
// WebCrypto Device-Resident Key Storage & P-256 Signing
// -------------------------------------------------------------
let _deviceCryptoKey = null;

async function getOrCreateDeviceKey() {
  if (_deviceCryptoKey) return _deviceCryptoKey;
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // non-extractable private key
      ["sign", "verify"]
    );
    _deviceCryptoKey = keyPair;
    return keyPair;
  } catch(e) {
    console.warn("WebCrypto generateKey error:", e);
    return null;
  }
}

async function signAndApprove(ch, payloadSize) {
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    alert("❌ Security Error: WebCrypto requires a Secure Context (HTTPS or localhost). Signing aborted.");
    return;
  }

  if (payloadSize > 65536) {
    alert("❌ Security Gate: Action argument payload exceeds maximum 64KB size limit. Signing aborted.");
    return;
  }
  const devId = getDeviceId();

  // 1. "What You See Is What You Sign": Hash the exact displayed argument text in DOM
  const pre = document.querySelector('#ch-' + ch.step_up_id + ' pre.args');
  const displayedArgs = pre ? pre.textContent : '';
  if (!displayedArgs) {
    alert("❌ Security Error: Displayed arguments not found in DOM. Signing aborted.");
    return;
  }
  const argsBytes = new TextEncoder().encode(displayedArgs);
  const argsDigest = await window.crypto.subtle.digest("SHA-256", argsBytes);
  const computedArgsHash = Array.from(new Uint8Array(argsDigest)).map(b => b.toString(16).padStart(2, '0')).join('');

  if (computedArgsHash.toLowerCase() !== ch.args_hash.toLowerCase()) {
    alert("❌ Security Violation: Displayed argument hash (" + computedArgsHash + ") does NOT match server challenge args_hash (" + ch.args_hash + ")! Tampering detected. Signing aborted.");
    return;
  }

  // 2. Recompute challenge hash using verified computedArgsHash
  const rawChallenge = "CHALLENGE_V2|" + ch.device_id + "|" + ch.tool_name + "|" + computedArgsHash + "|" + ch.nonce + "|" + ch.expiry + "|" + ch.taint_epoch + "|" + ch.challenge_seq;
  const rawBytes = new TextEncoder().encode(rawChallenge);
  const digestBuffer = await window.crypto.subtle.digest("SHA-256", rawBytes);
  const localHashHex = Array.from(new Uint8Array(digestBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

  if (localHashHex.toLowerCase() !== ch.challenge_hash.toLowerCase()) {
    alert("❌ Security Violation: Locally recomputed challenge hash does not match server challenge! Signing aborted.");
    return;
  }

  if (typeof ch.expected_counter !== 'number') {
    alert("❌ Security Error: Monotonic counter missing from server challenge. Signing aborted.");
    return;
  }

  // 3. Perform asymmetric cryptographic signature (Fail-Closed on error)
  let signatureHex = "";
  try {
    const keyPair = await getOrCreateDeviceKey();
    if (!keyPair || !keyPair.privateKey) {
      alert("❌ WebCrypto Error: Keypair generation or retrieval failed. Signing aborted.");
      return;
    }
    const challengeBytes = new TextEncoder().encode(ch.challenge_hash);
    const sigBuffer = await window.crypto.subtle['sign'](
      { name: "ECDSA", hash: { name: "SHA-256" } },
      keyPair.privateKey,
      challengeBytes
    );
    signatureHex = Array.from(new Uint8Array(sigBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch(err) {
    alert("❌ Signing Error: Cryptographic signing threw exception: " + err);
    return; // STOP IMMEDIATELY! NEVER SEND EMPTY SIGNATURE
  }

  if (!signatureHex) {
    alert("❌ Signing Error: Empty signature produced. Submission aborted.");
    return;
  }

  const sigPayload = {
    step_up_id: ch.step_up_id,
    device_id: devId,
    counter: ch.expected_counter,
    signature: signatureHex
  };

  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token') || sessionStorage.getItem('homie_token') || localStorage.getItem('homie_token') || '';

  try {
    const res = await fetch('/api/submit-approval', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(sigPayload)
    });
    const result = await res.json();
    if (result.success) {
      alert("✅ Action approved and verified by PC supervisor!");
    } else {
      alert("❌ Approval rejected: " + result.message);
    }
    refreshChallenges();
  } catch(e) {
    alert("Network error submitting approval: " + e);
  }
}

async function denyChallenge(stepUpId) {
  const devId = getDeviceId();
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token') || sessionStorage.getItem('homie_token') || localStorage.getItem('homie_token') || '';
  try {
    await fetch('/api/deny-challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ step_up_id: stepUpId, device_id: devId })
    });
  } catch(e) {
    console.warn("Deny challenge error:", e);
  }
  const el = document.getElementById('ch-' + stepUpId);
  if (el) el.remove();
  const container = document.getElementById('challenges-container');
  if (container.children.length === 0) {
    document.getElementById('empty-state').style.display = 'block';
  }
}

setInterval(refreshChallenges, 2000);
refreshChallenges();
</script>
</body>
</html>
"""

def is_request_host_allowed(host_header: Optional[str]) -> bool:
    if not host_header:
        return False
    h = host_header.split(":")[0].strip().lower()
    allowed = {"localhost", "127.0.0.1", "::1"}
    conf = load_phone_config()
    cfg_host = (conf.get("host") or "").split(":")[0].strip().lower()
    if cfg_host and cfg_host != "0.0.0.0":
        allowed.add(cfg_host)
    return h in allowed


def is_request_origin_allowed(origin_header: Optional[str]) -> bool:
    if not origin_header:
        return True  # Direct browser navigation or non-browser client
    try:
        parsed = urllib.parse.urlparse(origin_header)
        h = (parsed.hostname or "").lower()
        allowed = {"localhost", "127.0.0.1", "::1"}
        conf = load_phone_config()
        cfg_host = (conf.get("host") or "").split(":")[0].strip().lower()
        if cfg_host and cfg_host != "0.0.0.0":
            allowed.add(cfg_host)
        return h in allowed
    except Exception:
        return False


class PhoneGatewayHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard HTTP logs
        return

    def _send_response(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_response(200, "text/plain", "")

    def do_GET(self):
        headers = getattr(self, "headers", None) or {}
        host = headers.get("Host")
        if host and not is_request_host_allowed(host):
            self._send_response(403, "application/json", json.dumps({"error": "Forbidden: Invalid Host header (DNS rebinding protection)"}))
            return

        origin = headers.get("Origin")
        if origin and not is_request_origin_allowed(origin):
            self._send_response(403, "application/json", json.dumps({"error": "Forbidden: Untrusted cross-origin request rejected"}))
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/call":
            # Serve the mobile Duplex Web Audio Call Portal
            self._serve_web_phone_portal()
        elif path == "/approve":
            self._serve_phone_signing_portal()
        elif path == "/api/pending-challenges":
            self._handle_get_pending_challenges(parsed)
        elif path == "/remote":
            # Handled by mobile_remote module if available, or basic portal
            from mobile_remote import render_remote_html
            html = render_remote_html()
            self._send_response(200, "text/html; charset=utf-8", html)
        elif path == "/status":
            conf = load_phone_config()
            import action_broker
            ok, msg, res = action_broker.execute_action('homie_get_vitals', {}, caller_id='phone_gateway')
            try:
                vitals = json.loads(res) if ok and isinstance(res, str) else (res if isinstance(res, dict) else {})
            except Exception:
                vitals = {}
            data = {
                "status": "online",
                "phone_enabled": conf.get("enabled", True),
                "vitals": vitals
            }
            self._send_response(200, "application/json", json.dumps(data))
        else:
            self._send_response(404, "text/plain", "Not Found")

    def do_POST(self):
        headers = getattr(self, "headers", None) or {}
        host = headers.get("Host")
        if host and not is_request_host_allowed(host):
            self._send_response(403, "application/json", json.dumps({"error": "Forbidden: Invalid Host header (DNS rebinding protection)"}))
            return

        origin = headers.get("Origin")
        if origin and not is_request_origin_allowed(origin):
            self._send_response(403, "application/json", json.dumps({"error": "Forbidden: Untrusted cross-origin request rejected"}))
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_AUDIO_PAYLOAD_BYTES:
            self._send_response(413, "application/json", json.dumps({"error": f"PAYLOAD_TOO_LARGE: Content-Length {length} exceeds {MAX_AUDIO_PAYLOAD_BYTES} limit"}))
            return
        raw_body = self.rfile.read(length)
        body = raw_body.decode("utf-8", errors="ignore")

        # 1. Twilio Inbound Voice Webhook
        if path == "/voice" or path == "/voice/incoming":
            self._handle_twilio_incoming(body)
        elif path == "/voice/process":
            self._handle_twilio_process(body)
        elif path == "/api/web-call":
            self._handle_web_call_speech(body)
        elif path == "/api/audio-call":
            self._handle_audio_call(raw_body)
        elif path == "/api/pair":
            self._handle_device_pairing(body)
        elif path == "/api/complete-enrollment":
            self._handle_complete_enrollment(body)
        elif path == "/api/submit-approval":
            self._handle_submit_approval(body)
        elif path == "/api/deny-challenge":
            self._handle_deny_challenge(body)
        elif path == "/api/remote-action":
            self._handle_remote_action(body)
        else:
            self._send_response(404, "text/plain", "Endpoint not found")

    def _serve_phone_signing_portal(self):
        html = _get_signing_portal_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode("utf-8"))))
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _handle_deny_challenge(self, body):
        import phone_approval_portal
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        headers = getattr(self, "headers", None) or {}
        token = headers.get("X-Homie-Token", "") or headers.get("Authorization", "").replace("Bearer ", "") or (data.get("token") if isinstance(data, dict) else "")
        if not is_device_token_valid(token):
            self._send_response(401, "application/json", json.dumps({"error": "Unauthorized: Valid paired device token required"}))
            return

        step_up_id = data.get("step_up_id", "")
        dev_id = data.get("device_id", "primary_phone")
        ok, msg = phone_approval_portal.deny_approval_challenge(step_up_id, device_id=dev_id)
        status = 200 if ok else 404
        self._send_response(status, "application/json", json.dumps({"success": ok, "message": msg}))

    def _handle_get_pending_challenges(self, parsed):
        import phone_approval_portal
        # Authenticate caller device
        headers = getattr(self, "headers", None) or {}
        token = headers.get("X-Homie-Token", "") or headers.get("Authorization", "").replace("Bearer ", "")
        if not is_device_token_valid(token):
            self._send_response(401, "application/json", json.dumps({"error": "Unauthorized: Valid paired device token required"}))
            return

        query = urllib.parse.parse_qs(parsed.query)
        device_id = query.get("device_id", ["primary_phone"])[0]
        now = time.time()

        pending = []
        for sid, ch in list(phone_approval_portal._ACTIVE_CHALLENGES.items()):
            if ch.get("device_id") == device_id and ch.get("expiry", 0) > now:
                pending.append({
                    "step_up_id": ch["step_up_id"],
                    "device_id": ch["device_id"],
                    "tool_name": ch["tool_name"],
                    "arguments": ch["arguments"],
                    "canonical_args": ch.get("canonical_args", json.dumps(ch["arguments"], sort_keys=True, separators=(',', ':'))),
                    "args_hash": ch["args_hash"],
                    "nonce": ch["nonce"],
                    "expiry": ch["expiry"],
                    "taint_epoch": ch["taint_epoch"],
                    "challenge_seq": ch["challenge_seq"],
                    "expected_counter": ch.get("expected_counter", 1),
                    "challenge_hash": ch["challenge_hash"],
                    "canonical_prompt": ch["canonical_prompt"],
                    "session_id": ch["session_id"]
                })
        self._send_response(200, "application/json", json.dumps({"challenges": pending}))

    def _handle_complete_enrollment(self, body):
        import phone_approval_portal
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        sess_id = data.get("session_id", "")
        code = data.get("pairing_code", "")
        dev_id = data.get("device_id", "primary_phone")
        pub_pem = data.get("public_key_pem", "")
        primary_approval_sig = data.get("primary_approval_sig")

        ok, msg = phone_approval_portal.complete_device_enrollment(
            sess_id, code, dev_id, pub_pem, primary_approval_sig=primary_approval_sig
        )
        status = 200 if ok else 400
        self._send_response(status, "application/json", json.dumps({"success": ok, "message": msg}))

    def _handle_submit_approval(self, body):
        import phone_approval_portal
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        headers = getattr(self, "headers", None) or {}
        token = headers.get("X-Homie-Token", "") or headers.get("Authorization", "").replace("Bearer ", "") or (data.get("token") if isinstance(data, dict) else "")
        if not is_device_token_valid(token):
            self._send_response(401, "application/json", json.dumps({"error": "Unauthorized: Valid paired device token required"}))
            return

        step_up_id = data.get("step_up_id", "")
        sig = data.get("signature", "")
        dev_id = data.get("device_id", "primary_phone")
        counter = data.get("counter")
        if counter is not None:
            try:
                counter = int(counter)
            except (ValueError, TypeError):
                counter = None

        ok, msg, item = phone_approval_portal.verify_device_approval(
            step_up_id, sig, device_id=dev_id, counter=counter, is_authenticated_caller=True
        )
        status = 200 if ok else 400
        self._send_response(status, "application/json", json.dumps({
            "success": ok,
            "message": msg,
            "step_up_id": step_up_id
        }))

    def _serve_web_phone_portal(self):
        html = _get_call_page_html()
        self._send_response(200, "text/html; charset=utf-8", html)

    def _handle_twilio_incoming(self, form_body):
        """Generates TwiML response for incoming PSTN call with signature & allowlist verification."""
        params = urllib.parse.parse_qs(form_body)
        caller = params.get("From", ["Unknown"])[0]
        logger.info("Incoming phone call from: %s", caller)

        conf = load_phone_config()
        voice = conf.get("voice_name", "Polly.Danielle")

        # 1. Twilio Webhook Signature Validation
        auth_token = conf.get("twilio_auth_token", "").strip()
        if auth_token:
            sig = self.headers.get("X-Twilio-Signature", "")
            host = self.headers.get("Host", "localhost")
            proto = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
            url = f"{proto}://{host}{self.path}"
            flat_params = {k: v[0] for k, v in params.items()}
            if not validate_twilio_signature(url, flat_params, sig, auth_token):
                logger.warning("Rejected Twilio webhook: invalid X-Twilio-Signature")
                self._send_response(403, "text/plain", "Forbidden: Invalid Twilio signature")
                return

        # 2. Caller Allowlist Enforcement
        allowed_numbers = conf.get("allowed_numbers", [])
        if allowed_numbers:
            import re
            clean_caller = re.sub(r'[\s\-\(\)]', '', caller)
            clean_allowed = [re.sub(r'[\s\-\(\)]', '', num) for num in allowed_numbers]
            if clean_caller not in clean_allowed:
                logger.warning("Rejected incoming call from unauthorized number: %s", caller)
                twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="{voice}">Access denied. Your phone number is not authorized.</Say>
    <Hangup/>
</Response>"""
                self._send_response(200, "application/xml", twiml)
                return

        greeting = conf.get("voice_greeting", "Homie workstation online. How can I assist you?")

        # TwiML response with Gather
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="speech" action="/voice/process" method="POST" speechTimeout="auto" timeout="4">
        <Say voice="{voice}">{greeting}</Say>
    </Gather>
    <Say voice="{voice}">I did not hear anything. Goodbye!</Say>
    <Hangup/>
</Response>"""
        self._send_response(200, "application/xml", twiml)

    def _handle_twilio_process(self, form_body):
        """Processes user speech from Twilio and returns TwiML reply."""
        params = urllib.parse.parse_qs(form_body)
        speech = params.get("SpeechResult", [""])[0]
        caller = params.get("From", ["Unknown"])[0]
        conf = load_phone_config()
        voice = conf.get("voice_name", "Polly.Danielle")

        logger.info("Twilio speech from %s: %s", caller, speech)
        reply = execute_phone_instruction(speech, session_id=f"phone_{caller}")
        
        # Check if caller wants to hang up
        speech_lower = speech.lower()
        should_hangup = any(w in speech_lower for w in ["bye", "goodbye", "hang up", "exit", "quit", "done"])

        if should_hangup:
            twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="{voice}">{reply}. Goodbye!</Say>
    <Hangup/>
</Response>"""
        else:
            twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather input="speech" action="/voice/process" method="POST" speechTimeout="auto" timeout="4">
        <Say voice="{voice}">{reply}</Say>
    </Gather>
    <Say voice="{voice}">Call timed out. Goodbye!</Say>
    <Hangup/>
</Response>"""

        self._send_response(200, "application/xml", twiml)

    def _handle_device_pairing(self, json_body):
        try:
            data = json.loads(json_body) if json_body else {}
        except Exception:
            data = {}
        code = data.get("code", "")
        token, msg = exchange_pairing_code_for_token(code, device_name=data.get("name", "Mobile Phone"))
        if token:
            self._send_response(200, "application/json", json.dumps({"success": True, "token": token, "message": msg}))
        else:
            self._send_response(400, "application/json", json.dumps({"success": False, "message": msg}))

    def _handle_web_call_speech(self, json_body):
        """Handles speech text from Web Audio Duplex portal."""
        try:
            data = json.loads(json_body) if json_body else {}
        except Exception:
            data = {}

        speech = data.get("speech", "")
        pin = data.get("pin", "")
        token = data.get("token", "") or self.headers.get("Authorization", "").replace("Bearer ", "")
        # Check cryptographic token (fail closed - strictly requires valid device token)
        if not is_device_token_valid(token):
            self._send_response(401, "application/json", json.dumps({"reply": "Unauthorized: Valid device pairing token required."}))
            return

        reply = execute_phone_instruction(speech, session_id="web_call")
        
        # Synthesize audio for ultra-crisp offline voice playback
        audio_b64 = None
        try:
            import tempfile, voice, base64
            tmp_wav = os.path.join(tempfile.gettempdir(), f"homie_call_reply_{int(time.time()*1000)}.wav")
            voice.synthesize_speech_to_wav(reply, tmp_wav)
            if os.path.exists(tmp_wav):
                with open(tmp_wav, "rb") as wf:
                    audio_b64 = base64.b64encode(wf.read()).decode("ascii")
                try:
                    os.remove(tmp_wav)
                except Exception:
                    pass
        except Exception as e:
            logger.debug("TTS synthesis for phone call failed: %s", e)

        resp_payload = {"reply": reply}
        if audio_b64:
            resp_payload["audio_b64"] = audio_b64

        self._send_response(200, "application/json", json.dumps(resp_payload))

    def _handle_audio_call(self, raw_body):
        """Interactive Half-Duplex Push-to-Talk Voice Call: Processes raw or base64 audio upload from
        paired phone microphone.
        Enforces fail-closed authentication first, mandatory timestamp (+/-30s replay window) and nonce,
        bounded per-device nonces, pre-read and duration caps (<=5MB and <=30s), singlet confined STT worker,
        supervisor-side reversible tier cap, and safe atomic temporary files."""
        token = self.headers.get("X-Homie-Token", "") or self.headers.get("Authorization", "").replace("Bearer ", "")
        conf = load_phone_config()

        # 1. Authenticate FIRST (fail closed: no configurable disablement)
        is_auth = is_device_token_valid(token)
        if not is_auth:
            self._send_response(401, "application/json", json.dumps({"error": "Unauthorized: Valid paired device token required"}))
            return

        wav_bytes = b""
        data = {}
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                body_str = raw_body.decode("utf-8", errors="ignore") if isinstance(raw_body, bytes) else str(raw_body)
                data = json.loads(body_str)
                token = token or data.get("token", "")
                b64 = data.get("audio_b64", "")
                if b64:
                    import base64
                    wav_bytes = base64.b64decode(b64)
            except Exception:
                pass
        else:
            wav_bytes = raw_body if isinstance(raw_body, bytes) else raw_body.encode("latin1")

        # 2. Mandatory Replay Protection: Timestamp window (+/- 30s) and single-use Nonce
        ts_val = self.headers.get("X-Homie-Timestamp") or data.get("timestamp") or data.get("ts")
        nonce_val = self.headers.get("X-Homie-Nonce") or data.get("nonce")

        if not ts_val:
            self._send_response(400, "application/json", json.dumps({"error": "BAD_REQUEST: Missing required timestamp"}))
            return
        if not nonce_val:
            self._send_response(400, "application/json", json.dumps({"error": "BAD_REQUEST: Missing required nonce"}))
            return

        try:
            if abs(time.time() - float(ts_val)) > 30.0:
                self._send_response(401, "application/json", json.dumps({"error": "REPLAY_REJECTED: Timestamp is outside +/- 30s replay window"}))
                return
        except (ValueError, TypeError):
            self._send_response(400, "application/json", json.dumps({"error": "BAD_REQUEST: Malformed timestamp"}))
            return

        # Bounded per-device nonce store with TTL
        now = time.time()
        expired = [k for k, exp in _DEVICE_NONCES.items() if now > exp]
        for k in expired:
            del _DEVICE_NONCES[k]

        nonce_key = f"{token}:{nonce_val}"
        if nonce_key in _DEVICE_NONCES:
            self._send_response(401, "application/json", json.dumps({"error": "REPLAY_REJECTED: Nonce has already been consumed for this device"}))
            return
        _DEVICE_NONCES[nonce_key] = now + 60.0

        if not wav_bytes:
            self._send_response(400, "application/json", json.dumps({"error": "Missing audio payload"}))
            return

        # 3. Payload size cap (<= 5MB)
        if len(wav_bytes) > MAX_AUDIO_PAYLOAD_BYTES:
            self._send_response(413, "application/json", json.dumps({"error": f"PAYLOAD_TOO_LARGE: Audio payload {len(wav_bytes)} bytes exceeds 5MB limit"}))
            return

        # 4. Transcribe audio using singlet confined STT worker and enforce duration cap
        transcription = ""
        try:
            import io, wave, numpy as np
            with wave.open(io.BytesIO(wav_bytes), 'rb') as wf:
                framerate = wf.getframerate()
                n_frames = wf.getnframes()
                duration = float(n_frames) / float(framerate) if framerate > 0 else 0
                if duration > MAX_AUDIO_DURATION_SECS:
                    self._send_response(400, "application/json", json.dumps({"error": f"AUDIO_DURATION_EXCEEDED: Spoken audio length {duration:.1f}s exceeds 30.0s cap"}))
                    return

                n_channels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                frames = wf.readframes(n_frames)
                if sampwidth == 2:
                    arr = np.frombuffer(frames, dtype=np.int16).astype(np.float32) / 32768.0
                elif sampwidth == 1:
                    arr = (np.frombuffer(frames, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
                else:
                    arr = np.frombuffer(frames, dtype=np.int32).astype(np.float32) / 2147483648.0
                if n_channels > 1:
                    arr = arr[::n_channels]
                if framerate != 16000 and len(arr) > 0:
                    target_len = int(len(arr) * 16000 / framerate)
                    indices = np.linspace(0, len(arr) - 1, target_len)
                    arr = np.interp(indices, np.arange(len(arr)), arr)

            engine = get_shared_voice_engine()
            transcription = engine.transcribe(arr)
        except Exception as e:
            logger.warning("Local Whisper transcription failed: %s", e)

        # Fail closed on empty/unintelligible audio: NEVER execute unuttered fallback commands
        clean_transcript = (transcription or "").strip()
        if not clean_transcript:
            self._send_response(400, "application/json", json.dumps({"error": "TRANSCRIPTION_FAILED: Spoken audio could not be recognized or was silent"}))
            return

        # Execute phone instruction through ActionBroker with reversible tier cap
        reply = execute_phone_instruction(clean_transcript, session_id="audio_call")

        # 5. Synthesize reply audio into secure randomized temporary file
        audio_b64 = None
        try:
            import tempfile, voice, base64, secrets
            rand_token = secrets.token_hex(16)
            tmp_wav = os.path.join(tempfile.gettempdir(), f"homie_reply_{rand_token}.wav")
            voice.synthesize_speech_to_wav(reply, tmp_wav)
            if os.path.exists(tmp_wav):
                with open(tmp_wav, "rb") as wf:
                    audio_b64 = base64.b64encode(wf.read()).decode("ascii")
                try:
                    os.remove(tmp_wav)
                except Exception:
                    pass
        except Exception as e:
            logger.debug("TTS synthesis failed: %s", e)

        resp = {
            "transcription": clean_transcript,
            "reply": reply
        }
        if audio_b64:
            resp["audio_b64"] = audio_b64

        self._send_response(200, "application/json", json.dumps(resp))

    def _handle_remote_action(self, json_body):
        """Handles remote trackpad or presentation clicker action mediated by ActionBroker."""
        try:
            data = json.loads(json_body) if json_body else {}
        except Exception:
            data = {}

        token = data.get("token", "") or self.headers.get("Authorization", "").replace("Bearer ", "")
        pin = data.get("pin", "")
        conf = load_phone_config()

        is_auth = is_device_token_valid(token) or (conf.get("require_pin", True) and bool(pin) and str(pin) == str(conf.get("pin", "")))
        if not is_auth:
            self._send_response(401, "application/json", json.dumps({"success": False, "error": "Unauthorized"}))
            return

        action = data.get("action", "")
        import action_broker
        ok, msg, res = action_broker.execute_action(
            "homie_remote_trackpad", data, caller_id="phone_remote"
        )
        result = {"success": ok, "action": action, "message": msg}

        self._send_response(200, "application/json", json.dumps(result))

def start_phone_gateway(port=5055):
    """Starts the Phone Gateway HTTP server in a background daemon thread."""
    global _server_instance, _server_thread
    if _server_instance is not None:
        return True, f"Phone Gateway already running on port {port}"

    try:
        conf = load_phone_config()
        target_host = conf.get("host", "127.0.0.1")
        target_port = port or conf.get("port", 5055)
        _server_instance = HTTPServer((target_host, target_port), PhoneGatewayHandler)
        _server_thread = threading.Thread(target=_server_instance.serve_forever, daemon=True)
        _server_thread.start()
        logger.info("Phone Gateway successfully started on port %s", target_port)
        return True, f"Phone Gateway listening on port {target_port} (/call, /remote, /voice)"
    except Exception as e:
        logger.error("Failed to start Phone Gateway: %s", e)
        return False, str(e)

def stop_phone_gateway():
    """Stops the Phone Gateway HTTP server."""
    global _server_instance, _server_thread
    if _server_instance is None:
        return True, "Phone Gateway is not running."

    try:
        _server_instance.shutdown()
        _server_instance.server_close()
        _server_instance = None
        _server_thread = None
        return True, "Phone Gateway stopped."
    except Exception as e:
        return False, str(e)

if __name__ == "__main__":
    ok, msg = start_phone_gateway(5055)
    print("Start result:", ok, msg)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_phone_gateway()
