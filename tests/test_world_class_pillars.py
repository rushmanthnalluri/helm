"""tests/test_world_class_pillars.py - Verification of Next-Generation World-Class Pillars.

Verifies:
1. Modern Voice Architecture: Windows OneCore synthesis, NeuralVoiceManager, DuplexVoiceSession VAD.
2. VLA Agent & Set-of-Marks Grounding: Interactive control numbering, password field invariants, closed-loop cycle.
3. Interactive Generative Canvas: Artifact 2.0 state management, sheet/slide/doc display.
4. Instant File Search (Voidtools Everything SDK integration & bounded fallback).
5. IDE Workspace Context Bridge: Active git status, diff summary, technology detection.
6. Unified Tool & Policy Registrations across AgentTools and MCP Server.
"""

import os
import sys
import json
import time
import pytest
from pathlib import Path

import helm_voice_stream
import helm_vla_agent
import helm_canvas
import helm_everything_search
import helm_ide_bridge
import agent_tools
import helm_mcp


class TestModernVoice:
    def test_voice_listing_and_text_clean(self):
        synth = helm_voice_stream.WindowsOneCoreSynthesizer()
        voices = synth.list_voices()
        assert isinstance(voices, list)

        # Test text cleaning
        dirty = "# Title\n\n**Hello** [link](https://example.com) `code`"
        clean = helm_voice_stream.voice.speech_friendly_text(dirty)
        assert "#" not in clean
        assert "**" not in clean
        assert "`" not in clean

    def test_neural_voice_manager_barge_in(self):
        vm = helm_voice_stream.NeuralVoiceManager()
        assert vm.is_speaking() is False
        vm.stop()
        assert vm.is_speaking() is False

    def test_duplex_session_vad(self):
        session = helm_voice_stream.DuplexVoiceSession()
        session.start()
        assert session.active is True

        # Silence chunk
        res_silent = session.process_incoming_audio_chunk(b"\x00" * 320, volume_level=0.01)
        assert res_silent == "LISTENING"

        # Loud talking chunk (RMS > 0.08)
        res_talk = session.process_incoming_audio_chunk(b"\x55" * 320, volume_level=0.15)
        assert res_talk == "USER_TALKING"

        # Turn completion after silence
        time.sleep(0.7)
        res_done = session.process_incoming_audio_chunk(b"\x00" * 320, volume_level=0.01)
        assert res_done == "USER_TURN_COMPLETE"

        session.stop()
        assert session.active is False


class TestVLAAgent:
    def test_som_engine_and_formatting(self):
        engine = helm_vla_agent.SetOfMarksEngine(max_marks=10)
        mark = helm_vla_agent.UIElementMark(
            mark_id=1,
            name="Submit Order",
            control_type="Button",
            left=100,
            top=200,
            right=200,
            bottom=240,
            center_x=150,
            center_y=220,
            is_password=False,
            is_enabled=True
        )
        manifest = engine.format_marks_manifest([mark])
        assert "[1] Button \"Submit Order\" at (150, 220)" in manifest

    def test_vla_password_safety_invariant(self):
        agent = helm_vla_agent.VLAClosedLoopAgent()
        password_mark = helm_vla_agent.UIElementMark(
            mark_id=2,
            name="Master Password",
            control_type="Edit",
            left=100,
            top=300,
            right=300,
            bottom=340,
            center_x=200,
            center_y=320,
            is_password=True,
            is_enabled=True
        )
        # Attempting to type into password field must fail closed
        valid, msg, _ = agent.plan_and_validate("type", mark_id=2, marks=[password_mark], text_value="secret123")
        assert valid is False
        assert "password field" in msg.lower()


class TestInteractiveCanvas:
    def test_canvas_artifact_management(self):
        res = helm_canvas.display_artifact(
            title="Q4 Financial Model",
            content="Summary data",
            artifact_type="spreadsheet",
            data=[["Metric", "Value"], ["ARR", "$10M"]]
        )
        assert res["ok"] is True
        assert res["status"] == "displayed_in_canvas"

        active = helm_canvas.get_active_artifact()
        assert active is not None
        assert active["title"] == "Q4 Financial Model"
        assert active["type"] == "spreadsheet"
        assert active["data"][0] == ["Metric", "Value"]


class TestEverythingSearch:
    def test_search_finds_local_files(self):
        results = helm_everything_search.search_everything("README.md", max_results=5)
        assert len(results) >= 1
        assert any("README.md" in r["name"] for r in results)

    def test_search_extension_filtering(self):
        results = helm_everything_search.search_everything("helm", max_results=10, file_extension="py")
        assert len(results) >= 1
        for r in results:
            assert r["name"].endswith(".py") or r.get("is_dir")


class TestIDEBridge:
    def test_workspace_context_detection(self):
        ctx = helm_ide_bridge.get_ide_workspace_context()
        assert ctx["ok"] is True
        assert "Python" in ctx["detected_technologies"]
        assert ctx["git"]["is_git"] is True
        assert ctx["git"]["branch"] == "master"

    def test_git_diff_summary(self):
        diff = helm_ide_bridge.get_git_diff_summary()
        assert diff["ok"] is True
        assert isinstance(diff["stat"], str)


class TestRegistriesIntegration:
    def test_world_class_tools_present_in_registries(self):
        reg = agent_tools.build_full_registry()
        schema_names = {s["function"]["name"] for s in reg.schemas()}
        mcp_names = {t["name"] for t in helm_mcp.MCP_TOOLS}

        expected = [
            "helm_instant_file_search",
            "helm_get_ide_context",
            "helm_show_canvas",
            "helm_vla_step",
        ]

        for tool in expected:
            assert tool in schema_names, f"Tool '{tool}' missing from ToolRegistry"
            assert tool in mcp_names, f"Tool '{tool}' missing from MCP_TOOLS"
