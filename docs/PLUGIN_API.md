# Helm Plugin & Extension SDK Specification

Welcome to the **Helm Plugin SDK**. This guide provides the complete developer reference, security architecture, and step-by-step tutorial to build, test, and distribute production-grade Helm plugins in **under 15 minutes**.

---

## 1. Architectural Overview

Helm is designed with a **desktop-native, capability-sandboxed extension architecture**. Plugins extend Helm's core intelligence across two primary interfaces:

1. **LLM Agent Tools (`PluginTool`)**: Structured functions with JSON Schema parameters callable by Helm's reasoning engine to inspect local state, query web APIs, or automate desktop actions.
2. **Omnibar Commands (`PluginCommand`)**: Instant keyboard shortcuts (`Ctrl+Shift+...`) and palette commands directly invocable by human users from Helm's floating HUD.

```
                    ┌──────────────────────────────┐
                    │      Helm Agent Runtime      │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   PluginManager (Registry)   │
                    └──────┬───────────────┬───────┘
                           │               │
            ┌──────────────▼──────┐ ┌──────▼──────────────┐
            │   Security Sandbox  │ │  Lifecycle Hooks    │
            │   Capability Check  │ │(initialize/shutdown)│
            └──────────────┬──────┘ └──────┬──────────────┘
                           │               │
        ┌──────────────────▼───────────────▼──────────────────┐
        │                 Your Helm Plugin                    │
        │  ├── plugin.json  (Metadata & Permissions)          │
        │  └── plugin.py    (HelmPlugin, Tools, Commands)     │
        └─────────────────────────────────────────────────────┘
```

### Core Tenets
- **Declarative Manifests**: All permissions, tools, and shortcuts are declared in `plugin.json`.
- **Capability-Based Sandboxing**: Plugins cannot touch network, clipboard, filesystem, or OS system primitives without explicitly granted permissions.
- **Fail-Safe Isolation**: Tool execution runs in isolated threadpools with timeout enforcement and structured error recovery.
- **Zero-Friction Development**: Build and test plugins locally with Python and standard JSON.

---

## 2. Anatomy of a Helm Plugin

Every plugin lives in its own directory (e.g. `plugins/my-plugin/` or `~/.config/helm/plugins/my-plugin/`) and consists of:

```
my-plugin/
├── plugin.json       # Manifest declaring id, permissions, tools, and commands
├── plugin.py         # Python implementation extending HelmPlugin
└── README.md         # Documentation and setup instructions
```

---

## 3. The `plugin.json` Manifest Specification

The `plugin.json` manifest is the single source of truth for plugin identity, security boundaries, and tool contracts.

### Manifest Schema Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | **Yes** | Unique identifier matching regex `^[a-z0-9][a-z0-9_-]{1,63}$`. |
| `name` | `string` | **Yes** | Human-readable name displayed in the UI. |
| `version` | `string` | **Yes** | Semantic version string (e.g. `"1.0.0"`). |
| `author` | `string` | No | Author name or organization (default: `"Unknown"`). |
| `description` | `string` | No | Clear summary of plugin capabilities. |
| `category` | `string` | No | Category (`"Media"`, `"Productivity"`, `"Developer Tools"`, `"Weather"`, `"Utilities"`). |
| `icon` | `string` | No | Icon identifier (e.g. `"music"`, `"cloud-sun"`, `"calculator"`, `"book-open"`). |
| `permissions` | `list[str]` | No | Capability permissions requested by the plugin. |
| `commands` | `list[object]` | No | Quick actions exposed to the Omnibar keyboard palette. |
| `tools` | `list[object]` | No | Agent tools exposed to Helm's LLM reasoning loop. |

### Complete Example `plugin.json`

```json
{
  "id": "pomodoro",
  "name": "Pomodoro Focus Timer",
  "version": "1.0.0",
  "author": "Acme Dev",
  "description": "Desktop focus interval timer with notifications and status tracking.",
  "category": "Productivity",
  "icon": "clock",
  "permissions": ["system"],
  "commands": [
    {
      "id": "start_timer",
      "title": "Start Focus Interval",
      "description": "Start a 25-minute Pomodoro timer",
      "shortcut": "Ctrl+Shift+T",
      "handler": "start_focus"
    },
    {
      "id": "stop_timer",
      "title": "Stop Timer",
      "description": "Cancel active focus interval",
      "handler": "stop_focus"
    }
  ],
  "tools": [
    {
      "name": "pomodoro_start",
      "description": "Start a new focus interval for specified duration in minutes.",
      "python_callable": "plugin:start_focus",
      "parameters": {
        "type": "object",
        "properties": {
          "duration_minutes": {
            "type": "integer",
            "description": "Duration in minutes (default: 25)"
          },
          "task_label": {
            "type": "string",
            "description": "Optional name of the task being worked on"
          }
        }
      },
      "required_permissions": ["system"],
      "capability_tier": "ACTIONS",
      "timeout_seconds": 5.0
    },
    {
      "name": "pomodoro_status",
      "description": "Get current active focus timer status and remaining time.",
      "python_callable": "plugin:get_status",
      "parameters": {
        "type": "object",
        "properties": {}
      },
      "required_permissions": ["system"],
      "capability_tier": "READ_ONLY"
    }
  ]
}
```

---

## 4. Capability-Based Sandboxing & Security Model

Helm enforces capability gating based on the principle of least privilege. Permissions must be declared in `plugin.json` and are enforced at execution time by `SecuritySandbox`.

### Recognized Capabilities

| Capability | Scope / Purpose | Example Operations |
|---|---|---|
| `network` | Outbound HTTP/HTTPS requests, sockets, and remote APIs. | Querying GitHub, Notion, Weather, Webhooks. |
| `clipboard` | Reading or writing desktop system clipboard data. | Copying captured summaries, pasting snippets. |
| `filesystem` | File access outside the plugin's isolated data directory. | Reading local repo files, syncing note vaults. |
| `system` | OS integrations, hardware timers, local audio, calculator math. | Playing audio tones, evaluating math expressions. |

### Scoped Permissions
Permissions can be scoped to specific domains for finer control:
- `network:api.github.com`: Allows network access specifically to GitHub API endpoints.
- `network`: Broad permission granting network access to any remote host.

### Permission Gating in Python

You can guard methods declaratively or check permissions programmatically:

```python
# 1. Programmatic check via context
def my_tool_handler(**kwargs):
    context.require_permission("network")
    # ... perform request ...

# 2. Decorator guard via sandbox
@context.sandbox.guard("clipboard")
def copy_to_clipboard(text: str):
    ...
```

If an unauthorized action is attempted, `PermissionDeniedError` is raised and caught safely by `PluginManager`.

---

## 5. The Python SDK (`helm_plugin_sdk.py`)

The official SDK exposes clean object-oriented classes and lifecycle hooks.

### `HelmPlugin` Base Class

Every plugin subclass extends `HelmPlugin` and implements standard lifecycle hooks:

```python
from helm_plugin_sdk import HelmPlugin, PluginContext, PluginTool, PluginCommand

class MyCustomPlugin(HelmPlugin):
    def initialize(self) -> None:
        """Invoked when plugin is loaded. Setup caches, databases, or API clients."""
        self.logger.info("Initializing MyCustomPlugin")
        self.state_file = self.context.get_storage_path("state.json")

    def shutdown(self) -> None:
        """Invoked when plugin is unloaded or Helm exits. Clean up connections or timers."""
        self.logger.info("Shutting down MyCustomPlugin")

    def get_tools(self) -> list[PluginTool]:
        """Expose agent tools to Helm's LLM reasoning loop."""
        return [
            PluginTool(
                name="my_action",
                description="Performs a specific task",
                handler=self.handle_action,
                parameters={"type": "object", "properties": {"query": {"type": "string"}}},
                required_permissions=["network"],
                capability_tier="ACTIONS",
                timeout_seconds=10.0,
            )
        ]

    def get_commands(self) -> list[PluginCommand]:
        """Expose quick shortcuts to the Omnibar HUD."""
        return [
            PluginCommand(
                id="quick_action",
                title="Trigger Quick Action",
                description="Run action from shortcut",
                handler=self.handle_action,
                shortcut="Ctrl+Shift+A",
            )
        ]

    def handle_action(self, query: str = "", **kwargs):
        return {"ok": True, "result": f"Executed with query '{query}'"}
```

### `PluginContext` Services

Injected into each plugin instance via `self.context`:
- `self.context.plugin_id`: The unique string ID.
- `self.context.manifest`: The parsed `PluginManifest` object.
- `self.context.plugin_dir`: Directory containing the plugin's code.
- `self.context.data_dir`: Dedicated, isolated directory for this plugin's persistent state.
- `self.context.get_storage_path(filename)`: Returns a safe path inside `data_dir`.
- `self.context.logger`: Pre-configured Python logger (`helm.plugin.<plugin_id>`).
- `self.context.check_permission(perm)`: Returns boolean indicating if capability is granted.
- `self.context.require_permission(perm)`: Raises `PermissionDeniedError` if not granted.

---

## 6. Tutorial: Build a "Focus Timer" Plugin in < 15 Minutes

Follow these 4 steps to create a functional focus timer plugin:

### Step 1: Create the Directory
Inside your plugins directory (e.g. `plugins/focus-timer/`):
```bash
mkdir -p plugins/focus-timer
```

### Step 2: Create `plugins/focus-timer/plugin.json`
```json
{
  "id": "focus-timer",
  "name": "Focus Timer",
  "version": "1.0.0",
  "author": "Developer",
  "description": "Minimalist focus timer with status tracking.",
  "category": "Productivity",
  "icon": "clock",
  "permissions": ["system"],
  "commands": [
    {
      "id": "start",
      "title": "Start Focus Timer",
      "description": "Start a 25-minute timer",
      "shortcut": "Ctrl+Shift+F",
      "handler": "start_timer"
    }
  ],
  "tools": [
    {
      "name": "timer_start",
      "description": "Start focus timer for a given duration in minutes.",
      "python_callable": "plugin:start_timer",
      "parameters": {
        "type": "object",
        "properties": {
          "duration": {"type": "integer", "description": "Duration in minutes"}
        }
      },
      "required_permissions": ["system"]
    },
    {
      "name": "timer_status",
      "description": "Check current timer status.",
      "python_callable": "plugin:timer_status",
      "parameters": {"type": "object", "properties": {}},
      "required_permissions": ["system"]
    }
  ]
}
```

### Step 3: Implement `plugins/focus-timer/plugin.py`
```python
import time
from typing import Dict, Any, List
from helm_plugin_sdk import HelmPlugin, PluginTool, PluginCommand

class FocusTimerPlugin(HelmPlugin):
    def initialize(self) -> None:
        self.active_until: float = 0
        self.task_name: str = "Focus Session"

    def start_timer(self, duration: int = 25, **kwargs) -> Dict[str, Any]:
        self.active_until = time.time() + (duration * 60)
        return {
            "ok": True,
            "status": "running",
            "duration_minutes": duration,
            "message": f"Timer started for {duration} minutes.",
        }

    def timer_status(self, **kwargs) -> Dict[str, Any]:
        remaining = max(0, int(self.active_until - time.time()))
        is_active = remaining > 0
        return {
            "ok": True,
            "active": is_active,
            "remaining_seconds": remaining,
            "status": "running" if is_active else "idle",
        }

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="timer_start",
                description="Start focus timer",
                handler=self.start_timer,
                parameters={"type": "object", "properties": {"duration": {"type": "integer"}}},
                required_permissions=["system"],
            ),
            PluginTool(
                name="timer_status",
                description="Check timer status",
                handler=self.timer_status,
                parameters={"type": "object", "properties": {}},
                required_permissions=["system"],
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="start",
                title="Start Focus Timer",
                handler=self.start_timer,
                shortcut="Ctrl+Shift+F",
            )
        ]
```

### Step 4: Test in Python
```python
from helm_plugin_sdk import PluginManager

mgr = PluginManager()
plugin = mgr.load_plugin("focus-timer")
res = mgr.execute_tool("focus-timer", "timer_start", duration=25)
print(res)  # {'ok': True, 'status': 'running', 'duration_minutes': 25, ...}
```

---

## 7. Testing Your Plugin

Helm plugins can be tested cleanly with standard `pytest` fixtures.

```python
import pytest
from helm_plugin_sdk import PluginManager, parse_manifest

def test_plugin_discovery_and_execution(tmp_path):
    mgr = PluginManager(search_paths=["plugins"])
    discovered = mgr.discover_plugins()
    assert "focus-timer" in discovered

    plugin = mgr.load_plugin("focus-timer")
    assert plugin.is_initialized

    # Test tool invocation
    res = mgr.execute_tool("focus-timer", "timer_start", duration=10)
    assert res["ok"] is True
    assert res["duration_minutes"] == 10

def test_permission_enforcement():
    mgr = PluginManager(search_paths=["plugins"])
    mgr.load_plugin("focus-timer")
    
    # Revoke system permission
    mgr.revoke_permission("focus-timer", "system")
    res = mgr.execute_tool("focus-timer", "timer_start", duration=10)
    assert res["ok"] is False
    assert "Permission denied" in res["error"]
```

---

## 8. Built-in Plugins Reference

Helm ships with 5 production-grade built-in plugins:

### 1. `spotify` (Spotify Media Controller)
- **Directory**: `plugins/spotify/`
- **Permissions**: `["network", "system"]`
- **Tools**:
  - `spotify_play(query="")`: Resume or search and play track.
  - `spotify_pause()`: Pause active playback.
  - `spotify_now_playing()`: Return track title, artists, album, and progress.
  - `spotify_search(query, limit=5)`: Search Spotify catalog without playing.
  - `spotify_next()`: Skip to next track.
  - `spotify_previous()`: Skip to previous track.
- **Shortcuts**: `Ctrl+Shift+P` (Play), `Ctrl+Shift+Space` (Pause), `Ctrl+Shift+Right` (Next).

### 2. `notion` (Notion Quick Capture & Search)
- **Directory**: `plugins/notion/`
- **Permissions**: `["network", "clipboard"]`
- **Tools**:
  - `notion_quick_capture(text, title=None, tags=[])`: Capture note or task to Notion inbox.
  - `notion_search_pages(query, limit=5)`: Search workspace pages and databases.
  - `notion_create_page(title, content, parent_id=None)`: Create structured document.
  - `notion_get_page(page_id)`: Retrieve page metadata and blocks.
- **Shortcuts**: `Ctrl+Shift+N` (Capture Note), `Ctrl+Shift+O` (Search Pages).

### 3. `github` (GitHub Quick Query)
- **Directory**: `plugins/github/`
- **Permissions**: `["network"]`
- **Tools**:
  - `github_query_issues(repo, state="open", labels=None, limit=10)`: Query repository issues.
  - `github_query_prs(repo, state="open", limit=10)`: List pull requests.
  - `github_get_pr_details(repo, pr_number)`: Inspect diff stats, CI status, and reviewers.
  - `github_create_issue(repo, title, body="", labels=[])`: Create new issue.
- **Shortcuts**: `Ctrl+Shift+I` (Query Issues), `Ctrl+Shift+G` (Query PRs).

### 4. `weather` (Weather & Forecast Lookup)
- **Directory**: `plugins/weather/`
- **Permissions**: `["network"]`
- **API Key**: None required (wttr.in & open-meteo).
- **Tools**:
  - `weather_get_current(location)`: Real-time temperature (C & F), humidity, wind, and conditions.
  - `weather_get_forecast(location, days=3)`: Multi-day forecast with daily highs/lows.
  - `weather_quick_summary(location)`: Compact one-line glanceable summary.
- **Shortcuts**: `Ctrl+Shift+W` (Current Weather).

### 5. `converter` (Multi-Unit & Currency Converter)
- **Directory**: `plugins/converter/`
- **Permissions**: `["system"]`
- **Tools**:
  - `evaluate_math(expression)`: Safe AST mathematical evaluation (trig, powers, sqrt, logs, constants).
  - `convert_currency(amount, from_currency, to_currency)`: Global FX currency conversion.
  - `convert_timezone(from_tz, to_tz, time_str="now")`: Instant timezone translation.
  - `convert_units(value, from_unit, to_unit)`: Physical (length, mass, temperature) and data (MB, GB, TB) conversion.
- **Shortcuts**: `Ctrl+Shift+M` (Math Calc), `Ctrl+Shift+C` (Currency).

---

## 9. Distributing & Installing Plugins

### Local Development Directory
During development, Helm automatically detects plugins located in:
- Windows: `%USERPROFILE%\.config\helm\plugins\<plugin_id>\`
- macOS / Linux: `~/.config/helm/plugins/<plugin_id>/`

Or set the environment variable:
```bash
export HELM_PLUGINS_DIR="/path/to/my/plugins"
```

To enable a plugin in Helm, simply place the directory inside `HELM_PLUGINS_DIR` and reload Helm.
