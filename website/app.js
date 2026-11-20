/**
 * Helm — Interactive Landing Page Script
 * Powers an illustrative sample-flow preview. It does not control the desktop.
 */

// Demo Tab Content Definitions
const demoScenarios = [
  {
    title: "Local dictation flow",
    tag: "Illustrative source-code path · not a live desktop run",
    terminal: [
      { cls: "system", text: "Example: hold Ctrl+Alt+Space while the target app is focused" },
      { cls: "user", text: "Example: Helm records speech for local Whisper transcription" },
      { cls: "action", text: "Example: Unicode keyboard events are sent only if the target window is still foreground" },
      { cls: "system", text: "Source behavior is implemented; physical Windows app acceptance is pending" }
    ],
    metrics: ["Illustrative only · no measured timing or success-rate data"],
    actionText: "▶ Replay example"
  },
  {
    title: "Desktop Omnibar flow",
    tag: "Illustrative flow · timings not measured",
    terminal: [
      { cls: "system", text: "Example: press Alt+Space to open the Omnibar" },
      { cls: "user", text: "Example query: notion sprint" },
      { cls: "action", text: "Example: search and select a matching app, window, or item" },
      { cls: "system", text: "Results depend on the local Windows environment and enabled indexes" }
    ],
    metrics: ["Illustrative only · no indexed-item count or latency claim"],
    actionText: "▶ Replay example"
  },
  {
    title: "Route-specific approvals",
    tag: "Example policy flow · no approval is being performed",
    terminal: [
      { cls: "system", text: "Example: an action is classified by the route that will execute it" },
      { cls: "action", text: "Example: selected broker routes request Windows Hello" },
      { cls: "system", text: "Supervisor-protected actions additionally require enrolled-device evidence" },
      { cls: "user", text: "No enrolled device or invalid evidence means denial" }
    ],
    metrics: ["Illustrative only · no biometric or supervisor approval occurred"],
    actionText: "▶ Replay example"
  },
  {
    title: "Provider and data flow",
    tag: "Configuration example · not a live request",
    terminal: [
      { cls: "system", text: "Example: local Whisper handles dictation on-device by default" },
      { cls: "user", text: "Example: a selected cloud AI provider receives the prompt and included context" },
      { cls: "action", text: "Example: connected services receive data when their integration is invoked" },
      { cls: "system", text: "Review provider and integration settings before sending private data" }
    ],
    metrics: ["Illustrative only · no provider call or user data was sent"],
    actionText: "▶ Replay example"
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
    .map(m => `<span>${m}</span>`)
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
