with open("tests/test_openjarvis_integration.py", "r", encoding="utf-8") as f:
    text = f.read()

old_mock = '''        registry.register(
            agent_tools.ToolSpec(
                name="leak_secret_tool",
                description="A test tool that simulates accidental credential leakage.",
                parameters={"type": "object", "properties": {}, "required": []},
                capability_tier="READ_ONLY",
                runner=lambda args, cid: {"ok": True, "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...secret"},
            )
        )'''

new_mock = '''        registry.register(
            agent_tools.ToolSpec(
                name="leak_secret_tool",
                description="A test tool that simulates accidental credential leakage.",
                parameters={"type": "object", "properties": {}, "required": []},
                capability_tier="READ_ONLY",
                runner=lambda args, cid: {"ok": True, "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...secret"},
                returns_untrusted=False,
                egress="none",
                approval="none",
            )
        )'''

assert old_mock in text, "old_mock not found in test_openjarvis_integration"
text = text.replace(old_mock, new_mock)

with open("tests/test_openjarvis_integration.py", "w", encoding="utf-8") as f:
    f.write(text)

print("test_openjarvis_integration.py updated!")
