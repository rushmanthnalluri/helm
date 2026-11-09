import sys

# 1. Update homie_mcp.py
with open("homie_mcp.py", "r", encoding="utf-8") as f:
    mcp_text = f.read()

old_mcp_briefing = '''    {
        "name": "homie_generate_briefing",
        "description": "Generates a structured daily morning briefing from calendar tasks, meeting action items, workstation vitals, and user preferences.",
        "capabilityTier": "READ_ONLY",
        "returns_untrusted": False,'''

new_mcp_briefing = '''    {
        "name": "homie_generate_briefing",
        "description": "Generates a structured daily morning briefing from calendar tasks, meeting action items, workstation vitals, and user preferences.",
        "capabilityTier": "READ_ONLY",
        "returns_untrusted": True,'''

assert old_mcp_briefing in mcp_text, "old_mcp_briefing not found"
mcp_text = mcp_text.replace(old_mcp_briefing, new_mcp_briefing)

old_mcp_cs = '''    {
        "name": "homie_search_context",
        "description": "Searches local workstation context (quick notes, meeting transcripts, screen memory, and project documents) with SQLite FTS5 (BM25) and returns nonce-enveloped snippets.",
        "capabilityTier": "READ_ONLY",'''

new_mcp_cs = '''    {
        "name": "homie_search_context",
        "description": "Searches local workstation context (quick notes, meeting transcripts, screen memory, and project documents) with SQLite FTS5 (BM25) and returns nonce-enveloped snippets.",
        "capabilityTier": "SENSITIVE_READ",'''

assert old_mcp_cs in mcp_text, "old_mcp_cs not found"
mcp_text = mcp_text.replace(old_mcp_cs, new_mcp_cs)

with open("homie_mcp.py", "w", encoding="utf-8") as f:
    f.write(mcp_text)
print("homie_mcp.py updated!")

# 2. Update rails_config.py
with open("rails_config.py", "r", encoding="utf-8") as f:
    rails_text = f.read()

old_sens = '''COMPILED_IN_SENSITIVE_READS: frozenset[str] = frozenset({
    "homie_capture_screen",
    "homie_get_clipboard",
    "homie_read_screen_memory",
})'''

new_sens = '''COMPILED_IN_SENSITIVE_READS: frozenset[str] = frozenset({
    "homie_capture_screen",
    "homie_get_clipboard",
    "homie_read_screen_memory",
    "homie_search_context",
})'''

assert old_sens in rails_text, "old_sens not found"
rails_text = rails_text.replace(old_sens, new_sens)

with open("rails_config.py", "w", encoding="utf-8") as f:
    f.write(rails_text)
print("rails_config.py updated!")
