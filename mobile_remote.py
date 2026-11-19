"""Helm Mobile Remote & Presentation Deck.
Transforms any smartphone browser into a low-latency remote control for your Windows PC:
- Wireless Trackpad (relative touch movement, tap to click, two-finger right click, scroll)
- Media & Volume Deck (Play, Pause, Mute, Volume Up/Down)
- Presentation Clicker (Next/Prev slide, Fullscreen F5, Blank screen B)
- Remote Typing & Clipboard Sync (type on phone, pastes into active Windows application)
- Quick App & Window presets
"""

def render_remote_html():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Helm PC Remote</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; touch-action: manipulation; }
  body { background: #0d1117; color: #e6edf3; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
  
  .top-nav { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #161b22; border-bottom: 1px solid #30363d; }
  .top-nav h2 { font-size: 16px; font-weight: 600; color: #58a6ff; }
  .tabs { display: flex; gap: 8px; }
  .tab-btn { background: #21262d; border: 1px solid #30363d; color: #8b949e; padding: 6px 12px; border-radius: 8px; font-size: 12px; cursor: pointer; }
  .tab-btn.active { background: #1f6feb; color: #fff; border-color: #1f6feb; }

  .view { flex: 1; display: none; flex-direction: column; padding: 16px; }
  .view.active { display: flex; }

  /* Trackpad View */
  #trackpad-view { position: relative; }
  .trackpad-surface { flex: 1; background: #161b22; border: 2px dashed #30363d; border-radius: 16px; display: flex; justify-content: center; align-items: center; color: #484f58; font-size: 15px; user-select: none; touch-action: none; }
  .mouse-buttons { display: flex; gap: 12px; height: 60px; margin-top: 12px; }
  .btn-mouse { flex: 1; background: #21262d; border: 1px solid #30363d; border-radius: 12px; color: #c9d1d9; font-weight: 600; font-size: 15px; cursor: pointer; }
  .btn-mouse:active { background: #30363d; transform: scale(0.98); }

  /* Media & Deck View */
  .grid-deck { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 12px; }
  .card-deck { background: #161b22; border: 1px solid #30363d; border-radius: 14px; padding: 18px 12px; text-align: center; cursor: pointer; transition: all 0.1s; }
  .card-deck:active { transform: scale(0.96); background: #21262d; }
  .card-deck svg { width: 32px; height: 32px; fill: #58a6ff; margin-bottom: 8px; }
  .card-deck h3 { font-size: 14px; font-weight: 500; }

  /* Typing View */
  .type-container { display: flex; flex-direction: column; gap: 12px; }
  .input-text { background: #161b22; border: 1px solid #30363d; border-radius: 12px; color: #fff; padding: 14px; font-size: 15px; width: 100%; outline: none; }
  .input-text:focus { border-color: #58a6ff; }
  .btn-send-type { background: #238636; border: none; border-radius: 12px; color: white; padding: 14px; font-size: 15px; font-weight: 600; cursor: pointer; }
  .btn-send-type:active { transform: scale(0.98); }
</style>
</head>
<body>

<div class="top-nav">
  <h2>🏠 Helm Remote</h2>
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('trackpad')">Trackpad</button>
    <button class="tab-btn" onclick="switchTab('deck')">Media & Deck</button>
    <button class="tab-btn" onclick="switchTab('keyboard')">Type</button>
    <button class="tab-btn" onclick="location.href='/call'">Call</button>
  </div>
</div>

<!-- 1. Trackpad View -->
<div class="view active" id="trackpad-view">
  <div class="trackpad-surface" id="pad">Touch here to control cursor</div>
  <div class="mouse-buttons">
    <button class="btn-mouse" onclick="sendAction({action: 'click', button: 'left'})">Left Click</button>
    <button class="btn-mouse" onclick="sendAction({action: 'click', button: 'right'})">Right Click</button>
  </div>
</div>

<!-- 2. Media & Deck View -->
<div class="view" id="deck-view">
  <h3 style="font-size: 13px; color: #8b949e; margin-bottom: 8px;">PRESENTATION & SLIDES</h3>
  <div class="grid-deck">
    <div class="card-deck" onclick="sendAction({action: 'key', key: 'right'})">
      <svg viewBox="0 0 24 24"><path d="M5 13h11.86l-5.43 5.43 1.42 1.42L21.14 12l-8.29-7.85-1.42 1.42L16.86 11H5v2z"/></svg>
      <h3>Next Slide</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'key', key: 'left'})">
      <svg viewBox="0 0 24 24"><path d="M19 11H7.14l5.43-5.43-1.42-1.42L2.86 12l8.29 7.85 1.42-1.42L7.14 13H19v-2z"/></svg>
      <h3>Prev Slide</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'key', key: 'f5'})">
      <svg viewBox="0 0 24 24"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>
      <h3>Fullscreen</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'key', key: 'b'})">
      <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z"/></svg>
      <h3>Blank Screen</h3>
    </div>
  </div>

  <h3 style="font-size: 13px; color: #8b949e; margin: 20px 0 8px 0;">MEDIA CONTROLS</h3>
  <div class="grid-deck">
    <div class="card-deck" onclick="sendAction({action: 'media', command: 'play_pause'})">
      <svg viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
      <h3>Play / Pause</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'media', command: 'mute'})">
      <svg viewBox="0 0 24 24"><path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/></svg>
      <h3>Mute Audio</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'media', command: 'volume_up'})">
      <svg viewBox="0 0 24 24"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>
      <h3>Volume Up</h3>
    </div>
    <div class="card-deck" onclick="sendAction({action: 'media', command: 'volume_down'})">
      <svg viewBox="0 0 24 24"><path d="M18.5 12c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM5 9v6h4l5 5V4L9 9H5z"/></svg>
      <h3>Volume Down</h3>
    </div>
  </div>
</div>

<!-- 3. Type View -->
<div class="view" id="keyboard-view">
  <div class="type-container">
    <textarea class="input-text" id="typeInput" rows="4" placeholder="Type text to send to your PC active window..."></textarea>
    <button class="btn-send-type" onclick="sendType()">Type & Send to PC</button>
    <button class="btn-send-type" style="background: #1f6feb;" onclick="sendAction({action: 'key', key: 'enter'})">Send Enter Key</button>
    <button class="btn-send-type" style="background: #30363d;" onclick="sendAction({action: 'key', key: 'backspace'})">Backspace</button>
  </div>
</div>

<script>
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  if (tab === 'trackpad') {
    document.querySelectorAll('.tab-btn')[0].classList.add('active');
    document.getElementById('trackpad-view').classList.add('active');
  } else if (tab === 'deck') {
    document.querySelectorAll('.tab-btn')[1].classList.add('active');
    document.getElementById('deck-view').classList.add('active');
  } else if (tab === 'keyboard') {
    document.querySelectorAll('.tab-btn')[2].classList.add('active');
    document.getElementById('keyboard-view').classList.add('active');
  }
}

async function sendAction(data) {
  try {
    await fetch('/api/remote-action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  } catch(e) {
    console.error('Remote action failed:', e);
  }
}

function sendType() {
  const el = document.getElementById('typeInput');
  const val = el.value;
  if (!val) return;
  sendAction({ action: 'type', text: val });
  el.value = '';
}

// Trackpad logic
const pad = document.getElementById('pad');
let lastX = 0, lastY = 0;
let touching = false;
let startTime = 0;

pad.addEventListener('touchstart', (e) => {
  touching = true;
  startTime = Date.now();
  if (e.touches.length === 1) {
    lastX = e.touches[0].clientX;
    lastY = e.touches[0].clientY;
  }
}, { passive: false });

pad.addEventListener('touchmove', (e) => {
  if (!touching) return;
  e.preventDefault();
  if (e.touches.length === 1) {
    const curX = e.touches[0].clientX;
    const curY = e.touches[0].clientY;
    const dx = Math.round((curX - lastX) * 1.8);
    const dy = Math.round((curY - lastY) * 1.8);
    lastX = curX;
    lastY = curY;
    if (Math.abs(dx) > 0 || Math.abs(dy) > 0) {
      sendAction({ action: 'move', dx: dx, dy: dy });
    }
  } else if (e.touches.length === 2) {
    // 2-finger scroll
    const curY = e.touches[0].clientY;
    const dy = Math.round((curY - lastY) * 2);
    lastY = curY;
    if (Math.abs(dy) > 0) {
      sendAction({ action: 'scroll', dy: dy });
    }
  }
}, { passive: false });

pad.addEventListener('touchend', (e) => {
  const elapsed = Date.now() - startTime;
  if (elapsed < 150 && e.touches.length === 0) {
    // Tap to left click
    sendAction({ action: 'click', button: 'left' });
  }
  touching = false;
});
</script>
</body>
</html>"""
