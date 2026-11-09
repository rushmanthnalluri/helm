import os

with open("scripts/run_mutation_tests.py", "r", encoding="utf-8") as f:
    text = f.read()

target = '''    {
        "id": "MUTATION_99_FOREGROUND_WINDOW_MISSING_PROC_FAIL_CLOSED_BYPASS",
        "name": "Bypass Foreground Window Missing Proc/PID Fail-Closed Check in homie_supervisor.py",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": '            if not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name"):',
        "replacement": '            if False and (not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name")): # MUTATION BYPASS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_14_foreground_window_missing_fields_fails_closed_in_actuator"]
    }
]'''

replacement = '''    {
        "id": "MUTATION_99_FOREGROUND_WINDOW_MISSING_PROC_FAIL_CLOSED_BYPASS",
        "name": "Bypass Foreground Window Missing Proc/PID Fail-Closed Check in homie_supervisor.py",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": '            if not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name"):',
        "replacement": '            if False and (not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name")): # MUTATION BYPASS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_tier_a_adversarial.py::TestTierAAdversarialSuite::test_6_actuator_denies_when_foreground_missing_proc_name_or_pid"]
    },
    {
        "id": "MUTATION_100_OWNER_RIGHTS_ACE_DROP",
        "name": "Drop OWNER RIGHTS ACE (S-1-3-4) in homie_confinement.py",
        "file": os.path.join(BASE_DIR, "homie_confinement.py"),
        "target": '    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, limited_mask, sid_owner_rights)',
        "replacement": '    pass # MUTATION DROP OWNER RIGHTS ACE',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_tier_a_adversarial.py::TestTierAAdversarialSuite::test_5_windows_owner_rights_ace_denies_write_dac"]
    },
    {
        "id": "MUTATION_101_TOOLSPEC_CONTRACT_NO_DEFAULTS_BYPASS",
        "name": "Bypass ToolSpec Capability Tier Validation in agent_tools.py",
        "file": os.path.join(BASE_DIR, "agent_tools.py"),
        "target": '        if self.capability_tier not in VALID_CAPABILITY_TIERS:',
        "replacement": '        if False: # MUTATION BYPASS VALID_CAPABILITY_TIERS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_agent_tools.py::TestAgentTools::test_toolspec_contract_enforces_no_defaults_and_validates_fields"]
    },
    {
        "id": "MUTATION_102_CONTEXT_SEARCH_SENSITIVE_READ_DOWNGRADE",
        "name": "Downgrade Context Search from SENSITIVE_READ to READ_ONLY in agent_tools.py",
        "file": os.path.join(BASE_DIR, "agent_tools.py"),
        "target": '        capability_tier="SENSITIVE_READ",',
        "replacement": '        capability_tier="READ_ONLY", # MUTATION BYPASS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_context_search.py::TestContextSearch::test_5_tool_registry_and_mcp_execution"]
    },
    {
        "id": "MUTATION_103_QUARANTINE_READER_HANDLE_LEAK",
        "name": "Leak Raw Email Body into Planner Schema in homie_quarantine_reader.py",
        "file": os.path.join(BASE_DIR, "homie_quarantine_reader.py"),
        "target": '        body_handle = self.handle_store.store(body, prefix="EMAIL")',
        "replacement": '        body_handle = self.handle_store.store(body, prefix="EMAIL")\\n        schema["raw_body_leak"] = body # MUTATION LEAK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_tier_a_adversarial.py::TestTierAAdversarialSuite::test_1_adversarial_email_injection_zero_tool_call"]
    },
    {
        "id": "MUTATION_104_STRUCTURED_APPROVAL_BIDI_BYPASS",
        "name": "Bypass Prohibited Bidi/Zero-Width Characters Check in homie_structured_approval.py",
        "file": os.path.join(BASE_DIR, "homie_structured_approval.py"),
        "target": '        if cp in PROHIBITED_CODEPOINTS:',
        "replacement": '        if False: # MUTATION BYPASS PROHIBITED_CODEPOINTS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_structured_approval.py::TestStructuredApprovals::test_2_prohibits_bidi_override_characters"]
    },
    {
        "id": "MUTATION_105_BROWSER_BROKER_TOCTOU_BYPASS",
        "name": "Bypass DOM Mutation Anti-TOCTOU Check in homie_browser_broker.py",
        "file": os.path.join(BASE_DIR, "homie_browser_broker.py"),
        "target": '        if current_snap.snapshot_hash != prior_snapshot.snapshot_hash:',
        "replacement": '        if False: # MUTATION BYPASS DOM TOCTOU CHECK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_browser_broker.py::TestBrowserBroker::test_5_form_submission_anti_toctou_defense"]
    },
    {
        "id": "MUTATION_106_PLAN_ENVELOPE_TAINT_BYPASS",
        "name": "Bypass Plan Envelope Unexpected Taint Invalidation in homie_plan_envelopes.py",
        "file": os.path.join(BASE_DIR, "homie_plan_envelopes.py"),
        "target": '        if unexpected_taint_detected or current_taint_epoch > self.plan.taint_epoch:',
        "replacement": '        if False: # MUTATION BYPASS UNEXPECTED TAINT CHECK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_plan_envelopes.py::TestPlanEnvelopes::test_4_unexpected_taint_invalidates_plan"]
    }
]'''

assert target in text, "target not found"
text = text.replace(target, replacement)

with open("scripts/run_mutation_tests.py", "w", encoding="utf-8") as f:
    f.write(text)

print("SUCCESS: 106 mutations written to scripts/run_mutation_tests.py!")
