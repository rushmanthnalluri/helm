"""test_plugin_runtime.py - Comprehensive tests for the plugin runtime and Spotify plugin."""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import helm_plugins
import agent_tools


class TestPluginRuntime:
    def test_spotify_manifest_schema(self):
        """Verify the Spotify manifest schema declares all required tool fields."""
        manifest_path = Path(helm_plugins.BASE_DIR) / "plugins" / "spotify" / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert manifest["id"] == "spotify"
        assert "tools" in manifest
        tools = manifest["tools"]
        assert len(tools) >= 3

        tool_names = {t["name"] for t in tools}
        assert "spotify_play" in tool_names
        assert "spotify_pause" in tool_names
        assert "spotify_now_playing" in tool_names

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "python_callable" in tool
            assert "args_schema" in tool
            assert isinstance(tool["args_schema"], dict)

    def test_install_and_load_plugin_registers_tools(self, tmp_path, monkeypatch):
        """Verify install_from_community_catalog wires load_plugin automatically."""
        plugins_dir = tmp_path / "plugins"
        monkeypatch.setenv("HELM_PLUGINS_DIR", str(plugins_dir))

        # Clear any prior registered plugin tools
        agent_tools.unregister_plugin_tools("spotify")
        agent_tools.unregister_plugin_tools("spotify-controller")

        # Install Spotify from community catalog
        res = helm_plugins.install_from_community_catalog("spotify")
        assert res["ok"] is True
        assert res["id"] == "spotify"
        assert "spotify_play" in res.get("tools_loaded", [])

        # Verify tools are registered in agent_tools.PLUGIN_TOOL_REGISTRY
        assert "spotify_play" in agent_tools.PLUGIN_TOOL_REGISTRY
        assert "spotify_pause" in agent_tools.PLUGIN_TOOL_REGISTRY
        assert "spotify_now_playing" in agent_tools.PLUGIN_TOOL_REGISTRY

        # Verify ToolRegistry exposes plugin tools in schemas()
        registry = agent_tools.ToolRegistry()
        schemas = registry.schemas()
        schema_names = {s["function"]["name"] for s in schemas}
        assert "spotify_play" in schema_names
        assert "spotify_pause" in schema_names
        assert "spotify_now_playing" in schema_names

        # Disable plugin -> tools should unregister
        helm_plugins.set_plugin_enabled("spotify", False)
        assert "spotify_play" not in agent_tools.PLUGIN_TOOL_REGISTRY

        # Enable plugin -> tools should reload
        helm_plugins.set_plugin_enabled("spotify", True)
        assert "spotify_play" in agent_tools.PLUGIN_TOOL_REGISTRY

        # Uninstall plugin -> tools should unregister
        helm_plugins.uninstall_plugin("spotify")
        assert "spotify_play" not in agent_tools.PLUGIN_TOOL_REGISTRY

    def test_execute_plugin_tool_safely(self, tmp_path, monkeypatch):
        """Test safe execution of plugin tools with try/except and timeout handling."""
        plugins_dir = tmp_path / "plugins"
        monkeypatch.setenv("HELM_PLUGINS_DIR", str(plugins_dir))

        dummy_plugin_dir = plugins_dir / "custom-math"
        dummy_plugin_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "id": "custom-math",
            "name": "Custom Math Plugin",
            "version": "1.0.0",
            "description": "Math operations",
            "tools": [
                {
                    "name": "math_add",
                    "description": "Adds two numbers",
                    "python_callable": "plugin:add",
                    "args_schema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}
                },
                {
                    "name": "math_slow",
                    "description": "Slow hanging tool",
                    "python_callable": "plugin:slow_op",
                    "args_schema": {"type": "object", "properties": {}}
                },
                {
                    "name": "math_failing",
                    "description": "Always raises error",
                    "python_callable": "plugin:failing_op",
                    "args_schema": {"type": "object", "properties": {}}
                }
            ]
        }
        (dummy_plugin_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        plugin_code = (
            "import time\n"
            "def add(a, b):\n"
            "    return {'ok': True, 'sum': a + b}\n"
            "def slow_op():\n"
            "    time.sleep(1.0)\n"
            "    return {'ok': True}\n"
            "def failing_op():\n"
            "    raise ValueError('Simulated crash')\n"
        )
        (dummy_plugin_dir / "plugin.py").write_text(plugin_code, encoding="utf-8")

        # Load plugin
        load_res = helm_plugins.load_plugin("custom-math")
        assert load_res["ok"] is True
        assert "math_add" in load_res["tools_loaded"]

        # 1. Successful execution
        res = helm_plugins.execute_plugin_tool("custom-math", "math_add", a=5, b=7)
        assert res["ok"] is True
        assert res["sum"] == 12

        # Transparent execution via ToolRegistry.execute
        registry = agent_tools.ToolRegistry()
        reg_res = registry.execute("math_add", {"a": 20, "b": 22})
        assert reg_res["ok"] is True
        assert reg_res["sum"] == 42

        # 2. Timeout handling
        timeout_res = helm_plugins.execute_plugin_tool("custom-math", "math_slow", timeout_seconds=0.05)
        assert timeout_res["ok"] is False
        assert "timed out" in timeout_res["error"]

        # 3. Exception handling
        fail_res = helm_plugins.execute_plugin_tool("custom-math", "math_failing")
        assert fail_res["ok"] is False
        assert "Simulated crash" in fail_res["error"]

        # 4. Unknown tool
        unknown_res = helm_plugins.execute_plugin_tool("custom-math", "math_nonexistent")
        assert unknown_res["ok"] is False


class TestSpotifyPlugin:
    def test_spotify_play_with_mock_client(self):
        """Test spotify_play with search query and resume playback."""
        import sys
        spotify_path = str(Path(helm_plugins.BASE_DIR) / "plugins" / "spotify")
        if spotify_path not in sys.path:
            sys.path.insert(0, spotify_path)
        import plugin as spotify_plugin

        mock_sp = MagicMock()
        mock_sp.search.return_value = {
            "tracks": {
                "items": [
                    {
                        "name": "Bohemian Rhapsody",
                        "uri": "spotify:track:test1234",
                        "artists": [{"name": "Queen"}],
                        "album": {"name": "A Night at the Opera"}
                    }
                ]
            }
        }

        # 1. Play with query
        res = spotify_plugin.spotify_play(query="Bohemian Rhapsody", client=mock_sp)
        assert res["ok"] is True
        assert res["action"] == "play"
        assert res["track"] == "Bohemian Rhapsody"
        assert res["artist"] == "Queen"
        assert res["uri"] == "spotify:track:test1234"
        mock_sp.start_playback.assert_called_with(uris=["spotify:track:test1234"])

        # 2. Resume without query
        res_resume = spotify_plugin.spotify_play(query="", client=mock_sp)
        assert res_resume["ok"] is True
        assert res_resume["status"] == "resumed"

    def test_spotify_pause_with_mock_client(self):
        """Test spotify_pause."""
        import sys
        spotify_path = str(Path(helm_plugins.BASE_DIR) / "plugins" / "spotify")
        if spotify_path not in sys.path:
            sys.path.insert(0, spotify_path)
        import plugin as spotify_plugin

        mock_sp = MagicMock()
        res = spotify_plugin.spotify_pause(client=mock_sp)
        assert res["ok"] is True
        assert res["action"] == "pause"
        assert res["status"] == "paused"
        mock_sp.pause_playback.assert_called_once()

    def test_spotify_now_playing_with_mock_client(self):
        """Test spotify_now_playing returns track info or idle status."""
        import sys
        spotify_path = str(Path(helm_plugins.BASE_DIR) / "plugins" / "spotify")
        if spotify_path not in sys.path:
            sys.path.insert(0, spotify_path)
        import plugin as spotify_plugin

        mock_sp = MagicMock()
        mock_sp.current_playback.return_value = {
            "is_playing": True,
            "progress_ms": 45000,
            "item": {
                "name": "Hotel California",
                "uri": "spotify:track:eagles1",
                "artists": [{"name": "Eagles"}],
                "album": {"name": "Hotel California"},
                "duration_ms": 390000
            }
        }

        res = spotify_plugin.spotify_now_playing(client=mock_sp)
        assert res["ok"] is True
        assert res["is_playing"] is True
        assert res["track"] == "Hotel California"
        assert "Eagles" in res["artists"]
        assert res["duration_ms"] == 390000

        # When stopped
        mock_sp.current_playback.return_value = None
        mock_sp.current_user_playing_track.return_value = None
        res_stopped = spotify_plugin.spotify_now_playing(client=mock_sp)
        assert res_stopped["ok"] is True
        assert res_stopped["is_playing"] is False
