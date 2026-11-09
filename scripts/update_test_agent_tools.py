with open("tests/test_agent_tools.py", "r", encoding="utf-8") as f:
    text = f.read()

old_spec = '''def spec(runner, timeout=1.0, tier="READ_ONLY"):
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
        timeout_seconds=timeout,
    )'''

new_spec = '''def spec(runner, timeout=1.0, tier="READ_ONLY", returns_untrusted=False, egress="none", approval="none"):
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
    )'''

assert old_spec in text, "old_spec not found"
text = text.replace(old_spec, new_spec)

additional_tests = '''
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
'''

# Insert before if __name__ == "__main__":
target_insert = 'if __name__ == "__main__":'
assert target_insert in text
text = text.replace(target_insert, additional_tests + "\n\n" + target_insert)

with open("tests/test_agent_tools.py", "w", encoding="utf-8") as f:
    f.write(text)

print("SUCCESS: tests/test_agent_tools.py updated!")
