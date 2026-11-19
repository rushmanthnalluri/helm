"""test_plugin_ecosystem.py - Comprehensive Unit Tests for Helm Plugin SDK & Built-in Plugins.

Verifies:
- Plugin manifest parsing and validation
- Security sandbox & capability permission gating
- Plugin lifecycle hooks (initialize, shutdown)
- Plugin discovery and dynamic loading
- Tool registration, timeout handling, and execution
- Command registration and execution
- Agent tool registry integration
- All 5 production built-in plugins (spotify, notion, github, weather, converter)
"""

import os
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import helm_plugin_sdk
from helm_plugin_sdk import (
    HelmPlugin,
    PluginContext,
    PluginTool,
    PluginCommand,
    PluginManifest,
    SecuritySandbox,
    PluginManager,
    ManifestValidationError,
    PermissionDeniedError,
    parse_manifest,
)
import agent_tools


# ===========================================================================
# 1. Manifest Parsing and Validation Tests
# ===========================================================================

class TestPluginManifestValidation:
    def test_valid_manifest_parsing_from_dict(self):
        data = {
            "id": "sample-tool",
            "name": "Sample Tool Plugin",
            "version": "1.0.0",
            "author": "Helm Team",
            "description": "A sample plugin for tests",
            "permissions": ["network", "system"],
            "commands": [
                {"id": "run_sample", "title": "Run Sample", "shortcut": "Ctrl+Shift+S"}
            ],
            "tools": [
                {
                    "name": "sample_action",
                    "description": "Performs an action",
                    "parameters": {"type": "object", "properties": {"arg": {"type": "string"}}},
                    "required_permissions": ["network"]
                }
            ]
        }
        manifest = parse_manifest(data)
        assert manifest.id == "sample-tool"
        assert manifest.name == "Sample Tool Plugin"
        assert manifest.version == "1.0.0"
        assert "network" in manifest.permissions
        assert len(manifest.commands) == 1
        assert manifest.commands[0].id == "run_sample"
        assert len(manifest.tools) == 1
        assert manifest.tools[0].name == "sample_action"

    def test_valid_manifest_parsing_from_json_string(self):
        json_str = json.dumps({
            "id": "my_test_plugin",
            "name": "My Test Plugin",
            "version": "2.1.0"
        })
        manifest = parse_manifest(json_str)
        assert manifest.id == "my_test_plugin"
        assert manifest.version == "2.1.0"
        assert manifest.permissions == []
        assert manifest.icon == "puzzle"

    def test_manifest_validation_failures(self):
        # Missing id
        with pytest.raises(ManifestValidationError, match="Manifest 'id' is required"):
            parse_manifest({"name": "No ID", "version": "1.0.0"})

        # Invalid id regex (uppercase, spaces, special chars)
        with pytest.raises(ManifestValidationError, match="Invalid plugin id"):
            parse_manifest({"id": "Invalid ID", "name": "Bad ID", "version": "1.0.0"})

        with pytest.raises(ManifestValidationError, match="Invalid plugin id"):
            parse_manifest({"id": "plugin!name", "name": "Bad ID", "version": "1.0.0"})

        # Missing name
        with pytest.raises(ManifestValidationError, match="Manifest 'name' is required"):
            parse_manifest({"id": "valid-id", "name": "", "version": "1.0.0"})

        # Missing version
        with pytest.raises(ManifestValidationError, match="Manifest 'version' is required"):
            parse_manifest({"id": "valid-id", "name": "Valid Name", "version": ""})

        # Non-existent file path
        with pytest.raises(ManifestValidationError, match="does not exist"):
            parse_manifest("non_existent_manifest.json")

    def test_manifest_capabilities_backward_compatibility(self):
        # Fallback from 'capabilities' to 'permissions'
        data = {
            "id": "compat-test",
            "name": "Compat Test",
            "version": "1.0.0",
            "capabilities": ["network:api.test.com"]
        }
        manifest = parse_manifest(data)
        assert manifest.permissions == ["network:api.test.com"]


# ===========================================================================
# 2. Security Sandbox & Permission Gating Tests
# ===========================================================================

class TestSecuritySandbox:
    def test_permission_grant_and_check(self):
        sandbox = SecuritySandbox("test-plugin", ["network", "clipboard"])
        assert sandbox.has_permission("network") is True
        assert sandbox.has_permission("clipboard") is True
        assert sandbox.has_permission("filesystem") is False
        assert sandbox.has_permission("system") is False

    def test_scoped_permission_matching(self):
        # Broad permission 'network' should grant scoped 'network:api.github.com'
        sandbox = SecuritySandbox("test-plugin", ["network"])
        assert sandbox.has_permission("network:api.github.com") is True
        assert sandbox.has_permission("network:api.spotify.com") is True

        # Specific permission 'network:api.github.com' should NOT grant broad 'network'
        sandbox2 = SecuritySandbox("test-plugin", ["network:api.github.com"])
        assert sandbox2.has_permission("network:api.github.com") is True
        assert sandbox2.has_permission("network") is False
        assert sandbox2.has_permission("network:api.spotify.com") is False

    def test_wildcard_permission(self):
        sandbox = SecuritySandbox("admin-plugin", ["*"])
        assert sandbox.has_permission("network") is True
        assert sandbox.has_permission("system") is True
        assert sandbox.has_permission("clipboard") is True
        assert sandbox.has_permission("filesystem") is True

    def test_require_permission_raises(self):
        sandbox = SecuritySandbox("restricted-plugin", ["clipboard"])
        # Granted passes silently
        sandbox.require("clipboard")

        # Denied raises PermissionDeniedError
        with pytest.raises(PermissionDeniedError) as exc_info:
            sandbox.require("network")
        assert "lacks permission 'network'" in str(exc_info.value)
        assert exc_info.value.plugin_id == "restricted-plugin"
        assert exc_info.value.permission == "network"

    def test_sandbox_guard_decorator(self):
        sandbox = SecuritySandbox("guarded-plugin", ["system"])

        @sandbox.guard("system")
        def system_op():
            return 42

        @sandbox.guard("network")
        def network_op():
            return "ok"

        assert system_op() == 42
        with pytest.raises(PermissionDeniedError):
            network_op()


# ===========================================================================
# 3. Dynamic Plugin Manager & Lifecycle Tests
# ===========================================================================

class TestPluginManagerLifecycle:
    @pytest.fixture
    def test_plugin_dir(self, tmp_path):
        pdir = tmp_path / "custom-timer"
        pdir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "id": "custom-timer",
            "name": "Custom Timer",
            "version": "1.0.0",
            "permissions": ["system"],
            "commands": [
                {"id": "ping", "title": "Ping Timer", "handler": "ping_handler"}
            ],
            "tools": [
                {
                    "name": "timer_ping",
                    "description": "Pings the timer",
                    "python_callable": "plugin:ping_handler",
                    "parameters": {"type": "object", "properties": {}},
                    "required_permissions": ["system"]
                },
                {
                    "name": "timer_slow",
                    "description": "Slow operation",
                    "python_callable": "plugin:slow_handler",
                    "parameters": {"type": "object", "properties": {}},
                    "required_permissions": ["system"],
                    "timeout_seconds": 0.1
                },
                {
                    "name": "timer_fail",
                    "description": "Failing operation",
                    "python_callable": "plugin:fail_handler",
                    "parameters": {"type": "object", "properties": {}},
                    "required_permissions": ["system"]
                }
            ]
        }
        (pdir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")

        code = (
            "import time\n"
            "from helm_plugin_sdk import HelmPlugin, PluginTool, PluginCommand\n"
            "class CustomTimerPlugin(HelmPlugin):\n"
            "    def initialize(self):\n"
            "        self.initialized = True\n"
            "    def shutdown(self):\n"
            "        self.shutdown_called = True\n"
            "    def ping(self):\n"
            "        return {'ok': True, 'pong': True}\n"
            "    def slow(self):\n"
            "        time.sleep(1.0)\n"
            "        return {'ok': True}\n"
            "    def fail(self):\n"
            "        raise RuntimeError('Deliberate test error')\n"
            "    def get_tools(self):\n"
            "        return [\n"
            "            PluginTool('timer_ping', 'Ping', self.ping, required_permissions=['system']),\n"
            "            PluginTool('timer_slow', 'Slow', self.slow, required_permissions=['system'], timeout_seconds=0.1),\n"
            "            PluginTool('timer_fail', 'Fail', self.fail, required_permissions=['system']),\n"
            "        ]\n"
            "    def get_commands(self):\n"
            "        return [PluginCommand('ping', 'Ping Command', self.ping)]\n"
        )
        (pdir / "plugin.py").write_text(code, encoding="utf-8")
        return pdir

    def test_discover_and_load_plugin(self, test_plugin_dir):
        mgr = PluginManager(search_paths=[test_plugin_dir.parent])
        discovered = mgr.discover_plugins()
        assert "custom-timer" in discovered

        plugin = mgr.load_plugin("custom-timer")
        assert plugin.is_initialized is True
        assert mgr.get_plugin("custom-timer") is plugin
        assert mgr.is_plugin_enabled("custom-timer") is True

        tools = plugin.get_tools()
        assert len(tools) == 3
        commands = plugin.get_commands()
        assert len(commands) == 1

    def test_execute_tool_success_timeout_and_error(self, test_plugin_dir):
        mgr = PluginManager(search_paths=[test_plugin_dir.parent])
        mgr.load_plugin("custom-timer")

        # 1. Success execution
        res = mgr.execute_tool("custom-timer", "timer_ping")
        assert res["ok"] is True
        assert res["pong"] is True

        # 2. Timeout handling
        res_timeout = mgr.execute_tool("custom-timer", "timer_slow")
        assert res_timeout["ok"] is False
        assert "timed out" in res_timeout["error"]

        # 3. Exception handling
        res_fail = mgr.execute_tool("custom-timer", "timer_fail")
        assert res_fail["ok"] is False
        assert "Deliberate test error" in res_fail["error"]

    def test_execute_command(self, test_plugin_dir):
        mgr = PluginManager(search_paths=[test_plugin_dir.parent])
        mgr.load_plugin("custom-timer")

        cmd_res = mgr.execute_command("custom-timer", "ping")
        assert cmd_res["ok"] is True
        assert cmd_res["pong"] is True

    def test_permission_gating_on_tool_execution(self, test_plugin_dir):
        mgr = PluginManager(search_paths=[test_plugin_dir.parent])
        mgr.load_plugin("custom-timer")

        # Initially has 'system' permission -> succeeds
        assert mgr.execute_tool("custom-timer", "timer_ping")["ok"] is True

        # Revoke 'system' permission -> blocked
        mgr.revoke_permission("custom-timer", "system")
        res_denied = mgr.execute_tool("custom-timer", "timer_ping")
        assert res_denied["ok"] is False
        assert "Permission denied" in res_denied["error"]

        # Re-grant -> succeeds again
        mgr.grant_permission("custom-timer", "system")
        assert mgr.execute_tool("custom-timer", "timer_ping")["ok"] is True

    def test_enable_disable_and_unload_lifecycle(self, test_plugin_dir):
        mgr = PluginManager(search_paths=[test_plugin_dir.parent])
        plugin = mgr.load_plugin("custom-timer")

        # Disable
        mgr.disable_plugin("custom-timer")
        assert mgr.is_plugin_enabled("custom-timer") is False
        res = mgr.execute_tool("custom-timer", "timer_ping")
        assert res["ok"] is False
        assert "disabled" in res["error"]

        # Re-enable
        mgr.enable_plugin("custom-timer")
        assert mgr.is_plugin_enabled("custom-timer") is True
        assert mgr.execute_tool("custom-timer", "timer_ping")["ok"] is True

        # Unload
        unloaded = mgr.unload_plugin("custom-timer")
        assert unloaded is True
        assert getattr(plugin, "shutdown_called", False) is True
        assert mgr.get_plugin("custom-timer") is None


# ===========================================================================
# 4. Agent Tools Integration Tests
# ===========================================================================

class TestAgentToolsIntegration:
    def test_register_tools_with_agent(self, tmp_path):
        mgr = PluginManager(search_paths=[Path(__file__).parent.parent / "plugins"])
        mgr.load_plugin("converter")

        # Clear prior entries
        agent_tools.unregister_plugin_tools("converter")

        count = mgr.register_tools_with_agent()
        assert count >= 4
        assert "evaluate_math" in agent_tools.PLUGIN_TOOL_REGISTRY
        assert "convert_currency" in agent_tools.PLUGIN_TOOL_REGISTRY

        # Verify ToolRegistry sees them in schemas()
        registry = agent_tools.ToolRegistry()
        schemas = registry.schemas()
        schema_names = {s["function"]["name"] for s in schemas}
        assert "evaluate_math" in schema_names
        assert "convert_currency" in schema_names


# ===========================================================================
# 5. Built-in Plugin Tests: Spotify
# ===========================================================================

class TestBuiltinSpotifyPlugin:
    def test_spotify_plugin_loading_and_tools(self):
        mgr = PluginManager()
        plugin = mgr.load_plugin("spotify")
        assert plugin.plugin_id == "spotify"
        assert plugin.is_initialized is True

        tool_names = {t.name for t in plugin.get_tools()}
        assert "spotify_play" in tool_names
        assert "spotify_pause" in tool_names
        assert "spotify_now_playing" in tool_names
        assert "spotify_search" in tool_names
        assert "spotify_next" in tool_names
        assert "spotify_previous" in tool_names

        cmd_ids = {c.id for c in plugin.get_commands()}
        assert "play" in cmd_ids
        assert "pause" in cmd_ids
        assert "now_playing" in cmd_ids

    def test_spotify_tools_execution_with_mock(self):
        mgr = PluginManager()
        mgr.load_plugin("spotify")

        mock_sp = MagicMock()
        mock_sp.search.return_value = {
            "tracks": {
                "items": [
                    {
                        "name": "Imagine",
                        "uri": "spotify:track:imagine123",
                        "artists": [{"name": "John Lennon"}],
                        "album": {"name": "Imagine"},
                    }
                ]
            }
        }
        mock_sp.current_playback.return_value = {
            "is_playing": True,
            "progress_ms": 30000,
            "item": {
                "name": "Imagine",
                "uri": "spotify:track:imagine123",
                "artists": [{"name": "John Lennon"}],
                "album": {"name": "Imagine"},
                "duration_ms": 183000,
            }
        }

        # 1. Play track
        res_play = mgr.execute_tool("spotify", "spotify_play", query="Imagine", client=mock_sp)
        assert res_play["ok"] is True
        assert res_play["track"] == "Imagine"
        assert res_play["artist"] == "John Lennon"

        # 2. Pause
        res_pause = mgr.execute_tool("spotify", "spotify_pause", client=mock_sp)
        assert res_pause["ok"] is True
        assert res_pause["status"] == "paused"

        # 3. Now playing
        res_np = mgr.execute_tool("spotify", "spotify_now_playing", client=mock_sp)
        assert res_np["ok"] is True
        assert res_np["track"] == "Imagine"
        assert res_np["is_playing"] is True

        # 4. Search
        res_search = mgr.execute_tool("spotify", "spotify_search", query="Imagine", client=mock_sp)
        assert res_search["ok"] is True
        assert res_search["count"] == 1
        assert res_search["tracks"][0]["name"] == "Imagine"

        # 5. Next & Previous
        assert mgr.execute_tool("spotify", "spotify_next", client=mock_sp)["ok"] is True
        assert mgr.execute_tool("spotify", "spotify_previous", client=mock_sp)["ok"] is True


# ===========================================================================
# 6. Built-in Plugin Tests: Notion
# ===========================================================================

class TestBuiltinNotionPlugin:
    def test_notion_plugin_loading_and_tools(self):
        mgr = PluginManager()
        plugin = mgr.load_plugin("notion")
        assert plugin.plugin_id == "notion"
        assert plugin.is_initialized is True

        tool_names = {t.name for t in plugin.get_tools()}
        assert "notion_quick_capture" in tool_names
        assert "notion_search_pages" in tool_names
        assert "notion_create_page" in tool_names
        assert "notion_get_page" in tool_names

        cmd_ids = {c.id for c in plugin.get_commands()}
        assert "capture_note" in cmd_ids
        assert "search_pages" in cmd_ids

    def test_notion_quick_capture_and_search(self):
        mgr = PluginManager()
        mgr.load_plugin("notion")

        # 1. Quick capture
        cap_res = mgr.execute_tool(
            "notion",
            "notion_quick_capture",
            text="Buy groceries: milk, bread, coffee",
            title="Groceries List",
            tags=["errands", "shopping"]
        )
        assert cap_res["ok"] is True
        assert cap_res["title"] == "Groceries List"
        page_id = cap_res["id"]

        # 2. Search
        search_res = mgr.execute_tool("notion", "notion_search_pages", query="Groceries")
        assert search_res["ok"] is True
        assert search_res["count"] >= 1
        titles = [p["title"] for p in search_res["pages"]]
        assert "Groceries List" in titles

        # 3. Create structured page
        create_res = mgr.execute_tool(
            "notion",
            "notion_create_page",
            title="Project Architecture Spec",
            content="# Architecture Overview\nFull duplex audio and plugins."
        )
        assert create_res["ok"] is True
        created_id = create_res["id"]

        # 4. Get page
        get_res = mgr.execute_tool("notion", "notion_get_page", page_id=created_id)
        assert get_res["ok"] is True
        assert get_res["page"]["title"] == "Project Architecture Spec"


# ===========================================================================
# 7. Built-in Plugin Tests: GitHub
# ===========================================================================

class TestBuiltinGitHubPlugin:
    def test_github_plugin_loading_and_tools(self):
        mgr = PluginManager()
        plugin = mgr.load_plugin("github")
        assert plugin.plugin_id == "github"
        assert plugin.is_initialized is True

        tool_names = {t.name for t in plugin.get_tools()}
        assert "github_query_issues" in tool_names
        assert "github_query_prs" in tool_names
        assert "github_get_pr_details" in tool_names
        assert "github_create_issue" in tool_names

        cmd_ids = {c.id for c in plugin.get_commands()}
        assert "query_issues" in cmd_ids
        assert "query_prs" in cmd_ids
        assert "create_issue" in cmd_ids

    def test_github_queries_and_creation(self):
        mgr = PluginManager()
        mgr.load_plugin("github")

        # 1. Query issues
        issues_res = mgr.execute_tool("github", "github_query_issues", repo="helm/helm-desktop", state="open")
        assert issues_res["ok"] is True
        assert issues_res["count"] >= 1
        assert any("voice duplexing" in iss["title"].lower() for iss in issues_res["issues"])

        # 2. Query PRs
        prs_res = mgr.execute_tool("github", "github_query_prs", repo="helm/helm-desktop", state="open")
        assert prs_res["ok"] is True
        assert prs_res["count"] >= 1
        assert prs_res["prs"][0]["number"] == 42

        # 3. PR details
        pr_details = mgr.execute_tool("github", "github_get_pr_details", repo="helm/helm-desktop", pr_number=42)
        assert pr_details["ok"] is True
        assert pr_details["pr"]["head"] == "feature/voice-duplex"
        assert pr_details["pr"]["mergeable"] is True

        # 4. Create Issue
        create_res = mgr.execute_tool(
            "github",
            "github_create_issue",
            repo="helm/helm-desktop",
            title="Add Dark Mode to Omnibar",
            body="Implement CSS theme switcher for dark mode.",
            labels=["ui", "enhancement"]
        )
        assert create_res["ok"] is True
        assert create_res["number"] > 100
        assert create_res["title"] == "Add Dark Mode to Omnibar"


# ===========================================================================
# 8. Built-in Plugin Tests: Weather
# ===========================================================================

class TestBuiltinWeatherPlugin:
    def test_weather_plugin_loading_and_tools(self):
        mgr = PluginManager()
        plugin = mgr.load_plugin("weather")
        assert plugin.plugin_id == "weather"
        assert plugin.is_initialized is True

        tool_names = {t.name for t in plugin.get_tools()}
        assert "weather_get_current" in tool_names
        assert "weather_get_forecast" in tool_names
        assert "weather_quick_summary" in tool_names

        cmd_ids = {c.id for c in plugin.get_commands()}
        assert "current_weather" in cmd_ids
        assert "weather_forecast" in cmd_ids
        assert "quick_summary" in cmd_ids

    def test_weather_current_and_forecast(self):
        mgr = PluginManager()
        mgr.load_plugin("weather")

        # 1. Current weather (mock_only=True to guarantee deterministic fast offline test)
        res_curr = mgr.execute_tool("weather", "weather_get_current", location="Tokyo", mock_only=True)
        assert res_curr["ok"] is True
        assert res_curr["location"] == "Tokyo"
        assert "temperature_c" in res_curr
        assert "temperature_f" in res_curr
        assert "humidity" in res_curr
        assert "condition" in res_curr

        # 2. Forecast
        res_fc = mgr.execute_tool("weather", "weather_get_forecast", location="London", days=3, mock_only=True)
        assert res_fc["ok"] is True
        assert res_fc["days"] == 3
        assert len(res_fc["forecast"]) == 3

        # 3. Quick summary
        res_summary = mgr.execute_tool("weather", "weather_quick_summary", location="New York", mock_only=True)
        assert res_summary["ok"] is True
        assert "New York" in res_summary["summary"]


# ===========================================================================
# 9. Built-in Plugin Tests: Converter
# ===========================================================================

class TestBuiltinConverterPlugin:
    def test_converter_plugin_loading_and_tools(self):
        mgr = PluginManager()
        plugin = mgr.load_plugin("converter")
        assert plugin.plugin_id == "converter"
        assert plugin.is_initialized is True

        tool_names = {t.name for t in plugin.get_tools()}
        assert "evaluate_math" in tool_names
        assert "convert_currency" in tool_names
        assert "convert_timezone" in tool_names
        assert "convert_units" in tool_names

        cmd_ids = {c.id for c in plugin.get_commands()}
        assert "evaluate_math" in cmd_ids
        assert "convert_currency" in cmd_ids
        assert "convert_timezone" in cmd_ids
        assert "convert_units" in cmd_ids

    def test_evaluate_math_safe_ast(self):
        mgr = PluginManager()
        mgr.load_plugin("converter")

        # Basic operations
        assert mgr.execute_tool("converter", "evaluate_math", expression="12 * (5 + 3)")["result"] == 96
        # Powers and sqrt
        assert mgr.execute_tool("converter", "evaluate_math", expression="sqrt(144) + 2^4")["result"] == 28
        # Trigonometry and pi
        res_trig = mgr.execute_tool("converter", "evaluate_math", expression="round(sin(pi / 2))")
        assert res_trig["result"] == 1

        # Division by zero safety
        zero_res = mgr.execute_tool("converter", "evaluate_math", expression="10 / 0")
        assert zero_res["ok"] is False
        assert "Division by zero" in zero_res["error"]

        # Code injection prevention (e.g. __import__)
        inject_res = mgr.execute_tool("converter", "evaluate_math", expression="__import__('os').system('echo hi')")
        assert inject_res["ok"] is False

    def test_convert_currency(self):
        mgr = PluginManager()
        mgr.load_plugin("converter")

        # USD to EUR
        res = mgr.execute_tool("converter", "convert_currency", amount=100, from_currency="USD", to_currency="EUR")
        assert res["ok"] is True
        assert res["converted"] == 92.0
        assert res["from_currency"] == "USD"
        assert res["to_currency"] == "EUR"

        # GBP to JPY
        res2 = mgr.execute_tool("converter", "convert_currency", amount=10, from_currency="GBP", to_currency="JPY")
        assert res2["ok"] is True
        assert res2["converted"] > 0

        # Invalid currency
        res_inv = mgr.execute_tool("converter", "convert_currency", amount=50, from_currency="XYZ", to_currency="USD")
        assert res_inv["ok"] is False

    def test_convert_timezone(self):
        mgr = PluginManager()
        mgr.load_plugin("converter")

        # 14:00 UTC to JST (+9) -> 23:00
        res = mgr.execute_tool("converter", "convert_timezone", from_tz="UTC", to_tz="JST", time_str="14:00")
        assert res["ok"] is True
        assert "23:00 JST" in res["target_time"]

        # "now" mode
        res_now = mgr.execute_tool("converter", "convert_timezone", from_tz="EST", to_tz="PST", time_str="now")
        assert res_now["ok"] is True
        assert "EST" in res_now["source_time"]
        assert "PST" in res_now["target_time"]

    def test_convert_units(self):
        mgr = PluginManager()
        mgr.load_plugin("converter")

        # Length: km -> m
        res_len = mgr.execute_tool("converter", "convert_units", value=5, from_unit="km", to_unit="m")
        assert res_len["ok"] is True
        assert res_len["converted"] == 5000.0

        # Mass: kg -> lb
        res_mass = mgr.execute_tool("converter", "convert_units", value=1, from_unit="kg", to_unit="lb")
        assert res_mass["ok"] is True
        assert 2.20 <= res_mass["converted"] <= 2.21

        # Temperature: C -> F
        res_temp = mgr.execute_tool("converter", "convert_units", value=100, from_unit="C", to_unit="F")
        assert res_temp["ok"] is True
        assert res_temp["converted"] == 212.0

        # Data: GB -> MB
        res_data = mgr.execute_tool("converter", "convert_units", value=2, from_unit="gb", to_unit="mb")
        assert res_data["ok"] is True
        assert res_data["converted"] == 2048.0
