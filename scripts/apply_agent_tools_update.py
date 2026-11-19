import sys
import os

with open('agent_tools.py', 'r', encoding='utf-8') as f:
    text = f.read()

old_toolspec = '''@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    capability_tier: str
    runner: Callable[[dict[str, Any], str], Any]
    timeout_seconds: float = 5.0
    user_selected_guidance: bool = False
    taint_on_read: bool = False
    returns_untrusted: bool = False
    egress: str = "none"
    approval: str = "none"
    max_output_chars: int = MAX_TOOL_RESULT_CHARS

    def __post_init__(self):
        if self.taint_on_read and not self.returns_untrusted:
            object.__setattr__(self, "returns_untrusted", True)'''

new_toolspec = '''VALID_CAPABILITY_TIERS = frozenset({"READ_ONLY", "SENSITIVE_READ", "CONSEQUENTIAL", "WRITE_EXEC"})
VALID_APPROVAL_POLICIES = frozenset({"none", "step_up", "explicit", "phone_signed"})

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    capability_tier: str
    runner: Callable[[dict[str, Any], str], Any]
    returns_untrusted: bool
    egress: str
    approval: str
    timeout_seconds: float = 5.0
    user_selected_guidance: bool = False
    taint_on_read: bool = False
    max_output_chars: int = MAX_TOOL_RESULT_CHARS

    def __post_init__(self):
        if self.capability_tier not in VALID_CAPABILITY_TIERS:
            raise ValueError(
                f"Invalid capability_tier '{self.capability_tier}'. Must be one of {sorted(VALID_CAPABILITY_TIERS)}"
            )
        if self.egress != "none" and not self.egress.startswith("supervisor_proxy:"):
            raise ValueError(
                f"Invalid egress policy '{self.egress}'. Egress must be 'none' or 'supervisor_proxy:<allowlist>'"
            )
        if self.approval not in VALID_APPROVAL_POLICIES:
            raise ValueError(
                f"Invalid approval policy '{self.approval}'. Must be one of {sorted(VALID_APPROVAL_POLICIES)}"
            )
        if not isinstance(self.returns_untrusted, bool):
            raise TypeError("returns_untrusted must be a boolean (True or False)")
        if self.taint_on_read and not self.returns_untrusted:
            object.__setattr__(self, "returns_untrusted", True)'''

assert old_toolspec in text, "old_toolspec not found"
text = text.replace(old_toolspec, new_toolspec)

old_reg = 'if spec.capability_tier != "READ_ONLY" and not allow_consequential:'
new_reg = 'if spec.capability_tier not in ("READ_ONLY", "SENSITIVE_READ") and not allow_consequential:'
assert old_reg in text, "old_reg not found"
text = text.replace(old_reg, new_reg)

old_exec = 'if allowed_tier != "READ_ONLY":'
new_exec = 'if allowed_tier not in ("READ_ONLY", "SENSITIVE_READ"):'
assert old_exec in text, "old_exec not found"
text = text.replace(old_exec, new_exec)

# Update build_default_registry tool specs
old_vitals = '''    registry.register(ToolSpec(
        name="helm_get_vitals",
        description="Read current PC health, including memory, disk, battery, and uptime.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_get_vitals", args, caller_id),
    ))'''
new_vitals = '''    registry.register(ToolSpec(
        name="helm_get_vitals",
        description="Read current PC health, including memory, disk, battery, and uptime.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_get_vitals", args, caller_id),
        returns_untrusted=False,
        egress="none",
        approval="none",
    ))'''
assert old_vitals in text, "old_vitals not found"
text = text.replace(old_vitals, new_vitals)

old_downloads = '''    registry.register(ToolSpec(
        name="helm_list_downloads",
        description="List recent files in Downloads when the user asks which files they downloaded. Returns file names, paths, sizes, and modification times.",
        parameters={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 10}},
            "required": [],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_list_downloads", args, caller_id),
    ))'''
new_downloads = '''    registry.register(ToolSpec(
        name="helm_list_downloads",
        description="List recent files in Downloads when the user asks which files they downloaded. Returns file names, paths, sizes, and modification times.",
        parameters={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 10}},
            "required": [],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_list_downloads", args, caller_id),
        returns_untrusted=True,
        egress="none",
        approval="none",
        taint_on_read=True,
    ))'''
assert old_downloads in text, "old_downloads not found"
text = text.replace(old_downloads, new_downloads)

old_rem = '''    registry.register(ToolSpec(
        name="helm_remember_fact",
        description="Records or updates a durable personal fact about the user (e.g. name, preferences, work habits) that persists across restarts.",
        parameters={
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "fact": {"type": "string"},
            },
            "required": ["key", "fact"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_remember_fact", args, caller_id),
    ))'''
new_rem = '''    registry.register(ToolSpec(
        name="helm_remember_fact",
        description="Records or updates a durable personal fact about the user (e.g. name, preferences, work habits) that persists across restarts.",
        parameters={
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "fact": {"type": "string"},
            },
            "required": ["key", "fact"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_remember_fact", args, caller_id),
        returns_untrusted=False,
        egress="none",
        approval="none",
    ))'''
assert old_rem in text, "old_rem not found"
text = text.replace(old_rem, new_rem)

old_forget = '''    registry.register(ToolSpec(
        name="helm_forget_fact",
        description="Deletes a stale or outdated durable fact from the persistent memory store.",
        parameters={
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_forget_fact", args, caller_id),
    ))'''
new_forget = '''    registry.register(ToolSpec(
        name="helm_forget_fact",
        description="Deletes a stale or outdated durable fact from the persistent memory store.",
        parameters={
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_forget_fact", args, caller_id),
        returns_untrusted=False,
        egress="none",
        approval="none",
    ))'''
assert old_forget in text, "old_forget not found"
text = text.replace(old_forget, new_forget)

old_listfacts = '''    registry.register(ToolSpec(
        name="helm_list_facts",
        description="Lists all durable facts currently saved in the persistent memory store.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_list_facts", args, caller_id),
    ))'''
new_listfacts = '''    registry.register(ToolSpec(
        name="helm_list_facts",
        description="Lists all durable facts currently saved in the persistent memory store.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("helm_list_facts", args, caller_id),
        returns_untrusted=False,
        egress="none",
        approval="none",
    ))'''
assert old_listfacts in text, "old_listfacts not found"
text = text.replace(old_listfacts, new_listfacts)

old_listskills = '''    registry.register(ToolSpec(
        name="helm_list_skills",
        description="Lists the user's installed local Agent Skills. Use when the user asks what skills are available or you need to find a specifically requested skill.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_skill_catalog(args, caller_id),
    ))'''
new_listskills = '''    registry.register(ToolSpec(
        name="helm_list_skills",
        description="Lists the user's installed local Agent Skills. Use when the user asks what skills are available or you need to find a specifically requested skill.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_skill_catalog(args, caller_id),
        returns_untrusted=False,
        egress="none",
        approval="none",
    ))'''
assert old_listskills in text, "old_listskills not found"
text = text.replace(old_listskills, new_listskills)

old_readskill = '''    registry.register(ToolSpec(
        name="helm_read_skill",
        description="Reads one installed skill's instructions for the current task. Call only when the user explicitly asks to use a named skill; the skill provides guidance only and cannot bypass Helm's safety or approval rules.",
        parameters={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Exact installed skill name"}},
            "required": ["name"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_skill_read(args, caller_id),
        user_selected_guidance=True,
        taint_on_read=True,
    ))'''
new_readskill = '''    registry.register(ToolSpec(
        name="helm_read_skill",
        description="Reads one installed skill's instructions for the current task. Call only when the user explicitly asks to use a named skill; the skill provides guidance only and cannot bypass Helm's safety or approval rules.",
        parameters={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Exact installed skill name"}},
            "required": ["name"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_skill_read(args, caller_id),
        returns_untrusted=True,
        egress="none",
        approval="none",
        user_selected_guidance=True,
        taint_on_read=True,
    ))'''
assert old_readskill in text, "old_readskill not found"
text = text.replace(old_readskill, new_readskill)

# Update briefing returns_untrusted and taint_on_read
old_briefing = '''    registry.register(ToolSpec(
        name="helm_generate_briefing",
        description="Generates a structured daily morning briefing from calendar tasks, meeting action items, workstation vitals, and user preferences.",
        parameters={
            "type": "object",
            "properties": {"user_name": {"type": "string"}},
            "required": [],
        },
        capability_tier="READ_ONLY",
        returns_untrusted=False,
        egress="none",
        approval="none",
        max_output_chars=4000,
        runner=lambda args, caller_id: _run_briefing_tool(args, caller_id),
    ))'''
new_briefing = '''    registry.register(ToolSpec(
        name="helm_generate_briefing",
        description="Generates a structured daily morning briefing from calendar tasks, meeting action items, workstation vitals, and user preferences.",
        parameters={
            "type": "object",
            "properties": {"user_name": {"type": "string"}},
            "required": [],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_briefing_tool(args, caller_id),
        returns_untrusted=True,
        egress="none",
        approval="none",
        taint_on_read=True,
        max_output_chars=4000,
    ))'''
assert old_briefing in text, "old_briefing not found"
text = text.replace(old_briefing, new_briefing)

# Update context_search tier to SENSITIVE_READ
old_cs = '''    registry.register(ToolSpec(
        name="helm_search_context",
        description="Searches local workstation context (quick notes, meeting transcripts, screen memory, and project documents) with SQLite FTS5 (BM25) and returns nonce-enveloped snippets.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query or keywords"},
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional sources: quick_notes, meeting_notes, screen_memory"
                },
                "since": {"type": "number", "description": "Optional unix timestamp cutoff"},
                "limit": {"type": "integer", "description": "Max results (1-20)", "minimum": 1, "maximum": 20}
            },
            "required": ["query"],
        },
        capability_tier="READ_ONLY",
        returns_untrusted=True,
        egress="none",
        approval="none",
        max_output_chars=4000,
        runner=lambda args, caller_id: _run_context_search_tool(args, caller_id),
    ))'''
new_cs = '''    registry.register(ToolSpec(
        name="helm_search_context",
        description="Searches local workstation context (quick notes, meeting transcripts, screen memory, and project documents) with SQLite FTS5 (BM25) and returns nonce-enveloped snippets.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query or keywords"},
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional sources: quick_notes, meeting_notes, screen_memory"
                },
                "since": {"type": "number", "description": "Optional unix timestamp cutoff"},
                "limit": {"type": "integer", "description": "Max results (1-20)", "minimum": 1, "maximum": 20}
            },
            "required": ["query"],
        },
        capability_tier="SENSITIVE_READ",
        runner=lambda args, caller_id: _run_context_search_tool(args, caller_id),
        returns_untrusted=True,
        egress="none",
        approval="none",
        taint_on_read=True,
        max_output_chars=4000,
    ))'''
assert old_cs in text, "old_cs not found"
text = text.replace(old_cs, new_cs)

with open('agent_tools.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("SUCCESS: agent_tools.py updated!")
