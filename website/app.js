/**
 * Helm — Interactive Landing Page Script
 * Powers the interactive simulator tabs, clipboard helpers, and animations.
 */

// Demo Tab Content Definitions
const demoScenarios = [
  {
    title: "Voice & Caret Paste",
    tag: "Native Win32 SendInput · Silero VAD v5",
    terminal: [
      { cls: "system", text: "[00:00.018] Silero VAD v5: Speech detected (energy: 0.88, prob: 0.96)" },
      { cls: "user",   text: "[00:00.228] Audio input: \"Reply to Sarah confirming tomorrow's 2 PM sync and attach the slides.\"" },
      { cls: "system", text: "[00:00.245] Filler filter: Removed 0 disfluencies · Normalized casing and punctuation" },
      { cls: "action", text: "[00:00.251] SendInput: Active window target -> [Outlook - New Message]" },
      { cls: "success", text: "[00:00.257] Caret Insertion Complete: 12 words pasted seamlessly at active text cursor" }
    ],
    metrics: [
      "VAD Latency: 18ms",
      "Whisper Processing: 210ms",
      "Win32 Paste: 6ms",
      "Total: 234ms"
    ],
    actionText: "▶ Run Dictation Simulation"
  },
  {
    title: "Raycast-Class Omnibar",
    tag: "Start Menu Indexer · RapidFuzz 3.10 · 28ms Cold Pop",
    terminal: [
      { cls: "system", text: "[00:00.000] Hotkey Hook: Alt+Space intercepted" },
      { cls: "action", text: "[00:00.024] Omnibar popup rendered in 24ms via pywebview frameless layer" },
      { cls: "user",   text: "[00:00.080] Query: \"notion q4 sprint\"" },
      { cls: "system", text: "[00:00.088] RapidFuzz search across 4,120 indexed apps, open windows & shortcuts:" },
      { cls: "success", text: "  1. [Window] Notion - Q4 Engineering Sprint (Score: 98.4) [Alt+1]" },
      { cls: "system", text: "  2. [App] Notion Desktop (Score: 82.1) [Alt+2]" },
      { cls: "action", text: "[00:00.112] Enter key -> SetForegroundWindow invoked directly into active sprint doc" }
    ],
    metrics: [
      "Popup Latency: 24ms",
      "Search Speed: 8ms",
      "Indexed Items: 4,120",
      "Memory: 18MB"
    ],
    actionText: "▶ Run Omnibar Search"
  },
  {
    title: "Windows Hello Biometrics",
    tag: "WinRT Physical Step-Up Gate · Zero Phone Friction",
    terminal: [
      { cls: "system", text: "[00:00.005] User command: \"Clean up old project archives in D:\\Backups\"" },
      { cls: "system", text: "[00:00.012] Security Policy: Action involves bulk disk deletion (Tier-3 Risk)" },
      { cls: "action", text: "[00:00.015] Step-Up Gate triggered: Requesting Windows Hello UserConsentVerifier..." },
      { cls: "user",   text: "[00:00.650] Biometric hardware event: Windows Hello Fingerprint sensor matched (User: Sovereign)" },
      { cls: "success", text: "[00:00.658] WinRT Auth Token issued · HMAC-SHA256 signature stamped into tamper-evident audit ledger" },
      { cls: "system", text: "[00:00.672] AppContainer sandbox granted temporary write execution for 30 seconds" }
    ],
    metrics: [
      "Auth Protocol: WinRT UserConsent",
      "Ledger: SHA256 HMAC",
      "Sandbox: Windows AppContainer",
      "Status: Verified"
    ],
    actionText: "▶ Trigger Biometric Gate"
  },
  {
    title: "Hybrid Semantic Memory",
    tag: "Dual Engine: SQLite FTS5 (BM25) + ONNX 384-dim (sqlite-vec)",
    terminal: [
      { cls: "user",   text: "[00:00.002] Query: \"Where did we decide to host the vector embeddings?\"" },
      { cls: "system", text: "[00:00.008] Engine 1 (FTS5 Lexical): Scanned 12,840 local chat & file chunks" },
      { cls: "system", text: "[00:00.022] Engine 2 (ONNX Embedding): Computed 384-dim vector cosine similarity" },
      { cls: "action", text: "[00:00.026] Reciprocal Rank Fusion (RRF k=60): Merged candidate rankings" },
      { cls: "success", text: "[00:00.031] Top Fact (Score 0.94): \"We chose sqlite-vec with all-MiniLM-L6-v2 ONNX on-device.\"" }
    ],
    metrics: [
      "FTS5 Query: 6ms",
      "ONNX Inference: 14ms",
      "RRF Fusion: 5ms",
      "Total Recall: 25ms"
    ],
    actionText: "▶ Run Memory Recall"
  }
];

let currentTabIndex = 0;
let typingAnimationTimer = null;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
  switchDemoTab(0);
});

/**
 * Switch Demo Simulator Tab
 */
function switchDemoTab(index) {
  currentTabIndex = index;
  
  // Update sidebar active class
  const items = document.querySelectorAll(".sidebar-item");
  items.forEach((item, idx) => {
    item.classList.toggle("active", idx === index);
  });
  
  renderTabContent(demoScenarios[index]);
}

/**
 * Render Simulator Display
 */
function renderTabContent(scenario) {
  if (typingAnimationTimer) {
    clearTimeout(typingAnimationTimer);
  }
  
  const display = document.getElementById("demoDisplay");
  if (!display) return;
  
  const metricsHtml = scenario.metrics
    .map(m => `<span>• ${m}</span>`)
    .join("");
  
  display.innerHTML = `
    <div class="sim-container">
      <div class="sim-header">
        <span class="sim-tag">${scenario.tag}</span>
        <button class="btn btn-secondary sim-btn" onclick="rerunScenario()">${scenario.actionText}</button>
      </div>
      <div class="sim-terminal" id="simTerminal"></div>
      <div class="sim-metrics">${metricsHtml}</div>
    </div>
  `;
  
  animateTerminalLines(scenario.terminal);
}

/**
 * Animate Terminal Output Lines Sequentially
 */
function animateTerminalLines(lines) {
  const terminal = document.getElementById("simTerminal");
  if (!terminal) return;
  
  terminal.innerHTML = "";
  let lineIdx = 0;
  
  function step() {
    if (lineIdx >= lines.length) return;
    
    const lineData = lines[lineIdx];
    const div = document.createElement("div");
    div.className = `sim-line ${lineData.cls}`;
    div.textContent = lineData.text;
    terminal.appendChild(div);
    
    lineIdx++;
    typingAnimationTimer = setTimeout(step, 140);
  }
  
  step();
}

/**
 * Re-run current scenario animation
 */
function rerunScenario() {
  switchDemoTab(currentTabIndex);
}

/**
 * Copy WinGet command to clipboard with tooltip animation
 */
function copyWinget() {
  const cmd = "winget install Helm.DesktopAI";
  navigator.clipboard.writeText(cmd).then(() => {
    const box = document.getElementById("wingetBox");
    if (!box) return;
    
    const originalContent = box.innerHTML;
    box.innerHTML = `
      <code style="color: #10B981;">✓ Copied to clipboard!</code>
      <button class="copy-btn" title="Copied">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
      </button>
    `;
    
    setTimeout(() => {
      box.innerHTML = originalContent;
    }, 2400);
  }).catch(() => {
    // Fallback if clipboard API is denied
    prompt("Copy the installation command:", "winget install Helm.DesktopAI");
  });
}
