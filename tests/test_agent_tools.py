"""Focused validation, timeout, and least-privilege tests for the tool registry."""

import sys
import time
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_tools import ToolRegistry, ToolSpec, build_default_registry
import action_broker
import homie_supervisor


def spec(runner, timeout=1.0, tier="READ_ONLY", returns_untrusted=False, egress="none", approval="none"):
    return ToolSpec(
        name="sample_read",
        description="Read one bounded sample value.",
        parameters={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 5}},
            "required": ["limit"],
        },
        capability_tier=tier,
        runner=runner,
        returns_untrusted=returns_untrusted,
        egress=egress,
        approval=approval,
        timeout_seconds=timeout,
    )


class TestAgentTools(unittest.TestCase):
    @patch("homie_supervisor.get_allowed_tools_map", return_value={"sample_read": "READ_ONLY"})
    def test_arguments_validate_before_runner(self, _policy):
        calls = []
        registry = ToolRegistry()
        registry.register(spec(lambda args, caller_id: calls.append(args) or args))

        missing = registry.execute("sample_read", {})
        wrong_type = registry.execute("sample_read", {"limit": True})
        too_large = registry.execute("sample_read", {"limit": 6})
        extra = registry.execute("sample_read", {"limit": 2, "path": "secret"})

        self.assertFalse(missing["ok"])
        self.assertFalse(wrong_type["ok"])
        self.assertFalse(too_large["ok"])
        self.assertFalse(extra["ok"])
        self.assertEqual(calls, [])
        self.assertEqual(registry.execute("sample_read", {"limit": 2}), {"ok": True, "data": {"limit": 2}})

    def test_registry_rejects_write_tools_and_unknown_calls(self):
        registry = ToolRegistry()
        with self.assertRaisesRegex(ValueError, "not read-only"):
            registry.register(spec(lambda args, caller_id: None, tier="WRITE_EXEC"))
        self.assertFalse(registry.execute("send_chat_message", {"message": "hello"})["ok"])

    @patch("homie_supervisor.get_allowed_tools_map", return_value={"sample_read": "READ_ONLY"})
    def test_timeout_returns_structured_failure(self, _policy):
        registry = ToolRegistry()
        registry.register(spec(lambda args, caller_id: time.sleep(0.05), timeout=0.001))
        result = registry.execute("sample_read", {"limit": 1})
        self.assertFalse(result["ok"])
        self.assertIn("timed out", result["error"])

    @patch("action_broker.execute_action", return_value=(True, "Success", {"ram_pct": 42, "active_window": "Private title"}))
    @patch("homie_supervisor.get_allowed_tools_map", return_value={
        "homie_get_vitals": "READ_ONLY", "homie_list_downloads": "READ_ONLY"
    })
    def test_default_registry_routes_read_only_action_through_broker(self, _policy, execute_action):
        registry = build_default_registry()
        result = registry.execute("homie_get_vitals", {})
        self.assertEqual(result, {"ok": True, "data": {"ram_pct": 42}})
        execute_action.assert_called_once_with("homie_get_vitals", {}, caller_id="ai_text_agent")

    def test_tool_schemas_are_bounded_and_descriptive(self):
        registry = build_default_registry()
        schema = {tool["function"]["name"]: tool["function"] for tool in registry.schemas()}
        expected_core = {
            "homie_get_vitals",
            "homie_list_downloads",
            "homie_remember_fact",
            "homie_forget_fact",
            "homie_list_facts",
            "homie_list_skills",
            "homie_read_skill",
            "homie_generate_briefing",
            "homie_search_context",
        }
        self.assertTrue(expected_core.issubset(set(schema)))
        self.assertIn("recent files", schema["homie_list_downloads"]["description"])
        self.assertEqual(schema["homie_list_downloads"]["parameters"]["properties"]["limit"]["maximum"], 10)

    def test_close_cleans_only_an_unlocked_broker(self):
        supervisor = SimpleNamespace(state=homie_supervisor.STATE_ARMED)
        supervisor.clean_shutdown = Mock()
        broker = SimpleNamespace(supervisor=supervisor)
        registry = ToolRegistry()
        with patch.object(action_broker, "_GLOBAL_BROKER", broker):
            registry.close()
            supervisor.clean_shutdown.assert_called_once_with()
            self.assertIsNone(action_broker._GLOBAL_BROKER)

        locked_supervisor = SimpleNamespace(state=homie_supervisor.STATE_LOCKED)
        locked_supervisor.clean_shutdown = Mock()
        locked_broker = SimpleNamespace(supervisor=locked_supervisor)
        locked_registry = ToolRegistry()
        with patch.object(action_broker, "_GLOBAL_BROKER", locked_broker):
            locked_registry.close()
            locked_supervisor.clean_shutdown.assert_not_called()
            self.assertIs(action_broker._GLOBAL_BROKER, locked_broker)



    def test_toolspec_contract_enforces_no_defaults_and_validates_fields(self):
        """ToolSpec requires returns_untrusted, egress, and approval without defaults; rejects open egress."""
        # 1. Missing required field raises TypeError
        with self.assertRaises(TypeError):
            ToolSpec(
                name="invalid_tool",
                description="test",
                parameters={"type": "object", "properties": {}, "required": []},
                capability_tier="READ_ONLY",
                runner=lambda a, c: None,
            )

        # 2. Open egress 'user_specified' or arbitrary URL is strictly rejected
        with self.assertRaisesRegex(ValueError, "Invalid egress policy"):
            ToolSpec(
                name="bad_egress",
                description="test",
                parameters={"type": "object", "properties": {}, "required": []},
                capability_tier="READ_ONLY",
                runner=lambda a, c: None,
                returns_untrusted=False,
                egress="user_specified",
                approval="none",
            )

        # 3. Invalid capability tier is rejected
        with self.assertRaisesRegex(ValueError, "Invalid capability_tier"):
            ToolSpec(
                name="bad_tier",
                description="test",
                parameters={"type": "object", "properties": {}, "required": []},
                capability_tier="UNKNOWN_TIER",
                runner=lambda a, c: None,
                returns_untrusted=False,
                egress="none",
                approval="none",
            )

        # 4. Valid supervisor_proxy egress is accepted
        valid_proxy_tool = ToolSpec(
            name="proxy_tool",
            description="test",
            parameters={"type": "object", "properties": {}, "required": []},
            capability_tier="SENSITIVE_READ",
            runner=lambda a, c: None,
            returns_untrusted=True,
            egress="supervisor_proxy:api.example.com",
            approval="none",
        )
        self.assertEqual(valid_proxy_tool.egress, "supervisor_proxy:api.example.com")
        self.assertEqual(valid_proxy_tool.capability_tier, "SENSITIVE_READ")

    def test_default_registry_tools_comply_with_strict_5_field_contract(self):
        """Every tool registered in build_default_registry must satisfy strict contract."""
        registry = build_default_registry()
        for name, tool in registry._tools.items():
            self.assertIn(tool.capability_tier, {"READ_ONLY", "SENSITIVE_READ", "CONSEQUENTIAL", "WRITE_EXEC"})
            self.assertIsInstance(tool.returns_untrusted, bool)
            self.assertTrue(tool.egress == "none" or tool.egress.startswith("supervisor_proxy:"))
            self.assertIn(tool.approval, {"none", "step_up", "explicit", "phone_signed"})
            self.assertGreater(tool.max_output_chars, 0)

        # Context search is SENSITIVE_READ with taint
        cs = registry._tools["homie_search_context"]
        self.assertEqual(cs.capability_tier, "SENSITIVE_READ")
        self.assertTrue(cs.returns_untrusted)
        self.assertTrue(cs.taint_on_read)

        # Briefing tool carries taint
        briefing = registry._tools["homie_generate_briefing"]
        self.assertTrue(briefing.returns_untrusted)
        self.assertTrue(briefing.taint_on_read)


if __name__ == "__main__":
    unittest.main()
