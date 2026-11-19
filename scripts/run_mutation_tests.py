"""scripts/run_mutation_tests.py - Batch 27 Expanded Automated Mutation Test Harness.

Applies real code mutations across the critical defense layers to verify that:
1. Confinement File DACLs are truly defending sensitive assets (not cosmetic).
2. Confinement Job Object ActiveProcessLimit=1 is actively stopping fork-bombs / child spawns.
3. AppContainer token isolation is actively blocking network sockets.
4. Supervisor Actuator Complete Mediation is strictly verifying cryptographic intent tokens.
5. Policy Envelope domain scoping is actively preventing domain escapes.
6. Watchdog Low-Level Hook is actively rejecting synthetic injected keystrokes.
7. Phone Approval Portal is actively verifying Ed25519 asymmetric device signatures.
8. Ed25519 Update Verification is strictly enforcing asymmetric signatures.
9. Update Rollback Epoch Protection is strictly enforcing monotonic version increments.
10. Macro Anti-Taint Gate is strictly blocking macro registration when session or workstation is tainted.
11. Locked Recovery Approval Gate is strictly enforcing bound SignedActionApproval objects.
12. Action Approval Asymmetric Verification is mathematically preventing forgery from PC state.
13. Intent Token Sequence Binding is strictly binding client sequence to prevent desync replay.
14. Intent Token Arguments Binding is strictly verifying full 64-character SHA-256 arguments hashes.
15. Supervisor Tier Allowlist is enforcing complete mediation on every non-READ_ONLY tier.
16. Macro Fresh-Session Taint Dodge is strictly prevented by workstation-wide taint enforcement.
17. Action Approval Taint Epoch Gate is rejecting approvals from stale epochs.
18. Monotonic Counter Gate is strictly enforcing positive monotonic counters on device approvals.
19. Max Action Approval TTL Cap is rejecting forged approvals with excessive TTLs.
20. Unknown Tool Registry Gate is rejecting execution of unallowlisted tools in actuator.
21. Atomic Nonce Lock is preventing concurrent race replay conditions.
22. Second-Device Multi-Sig Gate is requiring primary device signature before enrolling additional devices.
23. Actuator Mandatory Sequence Number is strictly requiring positive sequence numbers.
24. Pending Challenges Authentication Gate is denying unauthenticated challenge listing.
25. Supervisor Fail-Open Gate is enforcing hard DENY when action privilege returns non-stepup deny.
26. Supervisor Dict Arguments Gate is rejecting non-dict arguments up front.
27. Supervisor Policy Envelope Gate is enforcing domain scoping & step limits inside _handle_propose.
28. Enrollment Active Device Multi-Sig Gate is preventing revoked primary phone bypass.
29. Enrollment Session-Bound V2 Multi-Sig Gate is preventing replay across sessions.
30. Global Persistent Enrollment Lockout Gate is blocking brute-force pairing attempts.

If any test suite stays green under a mutation, this script flags a CRITICAL FAILURE.
All mutations MUST be detected and killed (100% Mutation Kill Rate).
"""

import os
import sys
import shutil
import subprocess
import time
from typing import List, Dict, Any, Tuple

# Ensure UTF-8 console output on Windows
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


MUTATIONS = [
    {
        "id": "MUTATION_1_CONFINEMENT_FILE_DACL",
        "name": "Drop File Owner-Only DACL in helm_confinement.py",
        "file": os.path.join(BASE_DIR, "helm_confinement.py"),
        "target": "dacl = _owner_only_dacl(nsc.FILE_ALL_ACCESS)",
        "replacement": (
            "dacl = win32security.ACL()\n"
            "    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, nsc.FILE_ALL_ACCESS, _sid(ALL_APP_PACKAGES_SID))\n"
            "    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, nsc.FILE_ALL_ACCESS, _my_sid())"
        ),
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_confinement_attacks.py::TestBatch20VerifiedConfinement::test_confined_worker_attacks_with_specific_error_codes"]
    },
    {
        "id": "MUTATION_2_CONFINEMENT_JOB_LIMIT",
        "name": "Drop ActiveProcessLimit from Job Object in helm_confinement.py",
        "file": os.path.join(BASE_DIR, "helm_confinement.py"),
        "target": 'basic["ActiveProcessLimit"] = 1',
        "replacement": 'basic["ActiveProcessLimit"] = 0; basic["LimitFlags"] &= ~win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_confinement_attacks.py::TestBatch20VerifiedConfinement::test_confined_worker_attacks_with_specific_error_codes"]
    },
    {
        "id": "MUTATION_3_APPCONTAINER_NETWORK_ISOLATION",
        "name": "Remove AppContainer Isolation in helm_confinement.py",
        "file": os.path.join(BASE_DIR, "helm_confinement.py"),
        "target": "flags = EXTENDED_STARTUPINFO_PRESENT | win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW",
        "replacement": "flags = win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW; siex.lpAttributeList = None",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_confinement_attacks.py::TestBatch20VerifiedConfinement::test_confined_worker_attacks_with_specific_error_codes"]
    },
    {
        "id": "MUTATION_4_SUPERVISOR_COMPLETE_MEDIATION",
        "name": "Bypass Intent Token Verification in helm_supervisor.py",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        if tier != \"READ_ONLY\":\n            if not self.supervisor.verify_and_consume_intent_token(\n                intent_token, tool, args, caller_id, req_seq\n            ):\n                raise CompleteMediationBreachError(",
        "replacement": "        if False and tier != \"READ_ONLY\": # MUTATION BYPASS: Complete mediation disabled\n            if not self.supervisor.verify_and_consume_intent_token(\n                intent_token, tool, args, caller_id, req_seq\n            ):\n                raise CompleteMediationBreachError(",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_supervisor_actuator_requires_cryptographic_intent_token"]
    },
    {
        "id": "MUTATION_5_POLICY_ENVELOPE_DOMAIN_SCOPE",
        "name": "Bypass Browser Domain Scope Check in policy_envelope.py",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": 'return False, f"DENY: Browser domain \'{current_domain}\' outside envelope domain scope: {self.allowed_domains}"',
        "replacement": "pass # MUTATION BYPASS: domain scope check skipped",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch19_policy_envelope.py::TestBatch19PolicyEnvelope::test_browser_domain_scoping_enforcement"]
    },
    {
        "id": "MUTATION_6_WATCHDOG_SYNTHETIC_INJECTION",
        "name": "Drop Synthetic Keystroke Filter in helm_watchdog.py",
        "file": os.path.join(BASE_DIR, "helm_watchdog.py"),
        "target": "is_injected = bool(kb.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED))",
        "replacement": "is_injected = False # MUTATION BYPASS: synthetic input allowed",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch19_watchdog.py::TestBatch19WatchdogHardwareHook::test_synthetic_keystroke_hook_kills_worker"]
    },
    {
        "id": "MUTATION_7_PHONE_SIGNATURE_VERIFICATION",
        "name": "Bypass Ed25519 Signature Check in phone_approval_portal.py",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if not sig_ok:",
        "replacement": "if False: # MUTATION BYPASS: signature check skipped",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_tampered_signature_rejection"]
    },
    {
        "id": "MUTATION_8_ED25519_UPDATE_SIGNATURE_BYPASS",
        "name": "Bypass Ed25519 Signature Verification in update_verifier.py",
        "file": os.path.join(BASE_DIR, "update_verifier.py"),
        "target": "verifier.verify(canonical_data, sig_bytes)",
        "replacement": "pass # MUTATION BYPASS: Ed25519 signature verification skipped",
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_operations_and_recovery.TestOperationsAndRecovery.test_tampered_update_package_rejected"]
    },
    {
        "id": "MUTATION_9_UPDATE_ROLLBACK_EPOCH_BYPASS",
        "name": "Bypass Monotonic Version Epoch Rollback Check in update_verifier.py",
        "file": os.path.join(BASE_DIR, "update_verifier.py"),
        "target": "if new_epoch <= current_epoch:",
        "replacement": "if False: # MUTATION BYPASS: rollback check disabled",
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_operations_and_recovery.TestOperationsAndRecovery.test_rollback_epoch_rejection"]
    },
    {
        "id": "MUTATION_10_MACRO_TAINT_GATE_BYPASS",
        "name": "Bypass Macro Anti-Taint Laundering Check in skill_compiler.py",
        "file": os.path.join(BASE_DIR, "skill_compiler.py"),
        "target": 'if taint_tracker.is_session_tainted("macro_compilation") or taint_tracker.is_workstation_tainted():',
        "replacement": "if False: # MUTATION BYPASS: taint laundering check disabled",
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_skill_compiler_and_recovery.TestSkillCompilerAndRecovery.test_macro_compilation_denied_when_tainted"]
    },
    {
        "id": "MUTATION_11_LOCKED_RECOVERY_APPROVAL_BYPASS",
        "name": "Bypass Signed Approval Verification in locked_recovery.py",
        "file": os.path.join(BASE_DIR, "locked_recovery.py"),
        "target": "if not app_ok:",
        "replacement": "if False: # MUTATION BYPASS: approval verification disabled",
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_operations_and_recovery.TestOperationsAndRecovery.test_locked_recovery_flow"]
    },
    {
        "id": "MUTATION_12_ASYMMETRIC_APPROVAL_FORGERY_BYPASS",
        "name": "Bypass Asymmetric Signature Check in verify_action_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if not sig_ok:\n        return False, \"SIGNATURE_INVALID: Asymmetric Ed25519 signature failed verification\"",
        "replacement": "if False: pass # MUTATION BYPASS: action approval signature verification disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_asymmetric_phone_approval_unforgeability_from_pc_state"]
    },
    {
        "id": "MUTATION_13_INTENT_TOKEN_SEQ_BINDING_BYPASS",
        "name": "Bypass Sequence Binding in verify_and_consume_intent_token",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "if token_seq != seq:  # Strictly bind sequence number!",
        "replacement": "if False: # MUTATION BYPASS: seq check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_intent_token_sequence_binding_enforcement"]
    },
    {
        "id": "MUTATION_14_INTENT_TOKEN_ARGS_HASH_BYPASS",
        "name": "Bypass Arguments Hash Verification in verify_and_consume_intent_token",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "if not hmac.compare_digest(tok_args_hash, expected_args_hash):",
        "replacement": "if False: # MUTATION BYPASS: args hash check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_intent_token_args_hash_binding_enforcement"]
    },
    {
        "id": "MUTATION_15_SUPERVISOR_TIER_ALLOWLIST_BYPASS",
        "name": "Drop Tier Allowlist Check in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": 'if tier != "READ_ONLY":',
        "replacement": "if False: # MUTATION BYPASS: tier allowlist bypassed",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_supervisor_actuator_requires_cryptographic_intent_token"]
    },
    {
        "id": "MUTATION_16_MACRO_TAINT_DODGE_BYPASS",
        "name": "Bypass Workstation Taint Check in skill_compiler.py",
        "file": os.path.join(BASE_DIR, "skill_compiler.py"),
        "target": 'if taint_tracker.is_session_tainted("macro_compilation") or taint_tracker.is_workstation_tainted():',
        "replacement": 'if taint_tracker.is_session_tainted("macro_compilation") and False: # MUTATION BYPASS: workstation taint ignored',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_skill_compiler_and_recovery.TestSkillCompilerAndRecovery.test_macro_compilation_fresh_session_taint_dodge_rejected"]
    },
    {
        "id": "MUTATION_17_ACTION_APPROVAL_TAINT_EPOCH_BYPASS",
        "name": "Bypass Taint Epoch Verification in verify_action_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if approval_epoch != current_epoch:",
        "replacement": "if False: # MUTATION BYPASS: taint epoch check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_asymmetric_phone_approval_unforgeability_from_pc_state"]
    },
    {
        "id": "MUTATION_18_CROSS_DEVICE_APPROVAL_BYPASS",
        "name": "Bypass Cross-Device Binding in verify_device_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": 'if item.get("device_id") and device_id != item.get("device_id"):',
        "replacement": "if False: # MUTATION BYPASS: cross device check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_cross_device_approval_rejection"]
    },
    {
        "id": "MUTATION_19_DEVICE_RE_ENROLLMENT_OVERWRITE_BYPASS",
        "name": "Bypass Device Anti-Overwrite Gate in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        # Anti-overwrite invariant: Reject re-enrollment of already enrolled devices\n        if device_id in registry:",
        "replacement": "        # Anti-overwrite invariant: Reject re-enrollment of already enrolled devices\n        if False: # MUTATION BYPASS: allow device overwrite",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_enrollment_anti_overwrite_rejection"]
    },
    {
        "id": "MUTATION_20_MONOTONIC_COUNTER_CHECK_BYPASS",
        "name": "Bypass Mandatory Monotonic Counter in verify_device_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if counter is None:",
        "replacement": "if False: # MUTATION BYPASS: counter check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_counter_mandatory_rejection"]
    },
    {
        "id": "MUTATION_21_MAX_ACTION_APPROVAL_TTL_CAP_BYPASS",
        "name": "Bypass Max TTL Expiry Cap in verify_action_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if expiry > now + MAX_ACTION_APPROVAL_TTL:",
        "replacement": "if False: # MUTATION BYPASS: TTL cap disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch18_phone_portal.py::TestBatch18PhonePortal::test_max_action_approval_ttl_cap"]
    },
    {
        "id": "MUTATION_22_SUPERVISOR_UNKNOWN_TOOL_ACTUATOR_BYPASS",
        "name": "Bypass Tool Registry Allowlist in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "if tool not in allowed_tools:",
        "replacement": "if False: # MUTATION BYPASS: unknown tool check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_supervisor_actuator_rejects_unknown_tool"]
    },
    {
        "id": "MUTATION_23_ATOMIC_NONCE_LOCK_BYPASS",
        "name": "Bypass Atomic Nonce Check in verify_action_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "    with _NONCE_LOCK:\n        if is_nonce_consumed(nonce) or nonce in _PENDING_ACTION_NONCES:\n            return False, \"REPLAY_REJECTED: Approval nonce has already been consumed\"",
        "replacement": "    with _NONCE_LOCK:\n        if False and (is_nonce_consumed(nonce) or nonce in _PENDING_ACTION_NONCES): # MUTATION BYPASS: atomic nonce check disabled\n            return False, \"REPLAY_REJECTED: Approval nonce has already been consumed\"",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_4_concurrent_nonce_replay_race_condition"]
    },
    {
        "id": "MUTATION_24_SECOND_DEVICE_MULTISIG_BYPASS",
        "name": "Bypass Second Device Multi-Sig Gate in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "                if not primary_approval_sig:\n                    with _ENROLLMENT_LOCK:\n                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)\n                    return False, \"APPROVAL_REQUIRED: Adding a device requires cryptographic approval from an active device.\"",
        "replacement": "                if False: # MUTATION BYPASS: approval check bypassed\n                    pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_6_second_device_requires_primary_approval"]
    },
    {
        "id": "MUTATION_25_ACTUATOR_SEQ_REQUIRED_BYPASS",
        "name": "Bypass Mandatory Sequence Check in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": 'if seq is None or not isinstance(seq, int) or seq <= 0:\n            raise ValueError("Sequence number seq is strictly required and must be a positive integer!")',
        "replacement": 'if False: # MUTATION BYPASS: seq check disabled\n            pass',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_8_mandatory_sequence_number_rejection_of_fallback"]
    },
    {
        "id": "MUTATION_26_PENDING_CHALLENGES_AUTH_BYPASS",
        "name": "Bypass Authentication Gate in _handle_get_pending_challenges",
        "file": os.path.join(BASE_DIR, "phone_gateway.py"),
        "target": '    def _handle_get_pending_challenges(self, parsed):\n        import phone_approval_portal\n        # Authenticate caller device\n        headers = getattr(self, "headers", None) or {}\n        token = headers.get("X-Helm-Token", "") or headers.get("Authorization", "").replace("Bearer ", "")\n        if not is_device_token_valid(token):',
        "replacement": '    def _handle_get_pending_challenges(self, parsed):\n        import phone_approval_portal\n        # Authenticate caller device\n        headers = getattr(self, "headers", None) or {}\n        token = headers.get("X-Helm-Token", "") or headers.get("Authorization", "").replace("Bearer ", "")\n        if False: # MUTATION BYPASS: auth check disabled',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_3_unauthenticated_listing_and_challenge_cancellation_denied"]
    },
    {
        "id": "MUTATION_27_SUPERVISOR_FAIL_OPEN_BYPASS",
        "name": "Bypass Fail-Closed Gate on Non-StepUp Deny in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "            if not allowed:\n                if requires_step_up:",
        "replacement": "            if False: # MUTATION BYPASS: taint fail-closed gate disabled\n                if requires_step_up:",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_1_supervisor_fail_open_prevented_on_non_stepup_deny"]
    },
    {
        "id": "MUTATION_28_SUPERVISOR_NON_DICT_ARGS_BYPASS",
        "name": "Bypass Strict Dict Argument Validation in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        if not isinstance(args, dict):\n            return self._encode_reply(MSG_ERROR, {",
        "replacement": "        if False: # MUTATION BYPASS: non-dict args check disabled\n            return self._encode_reply(MSG_ERROR, {",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_2_supervisor_rejects_non_dict_arguments"]
    },
    {
        "id": "MUTATION_29_SUPERVISOR_ENVELOPE_BYPASS",
        "name": "Bypass Policy Envelope Check in PolicySupervisor._handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        ks_to_commit = 0\n        res_token = None\n        if getattr(self, \"envelope\", None) and getattr(self.envelope, \"is_active\", False):",
        "replacement": "        ks_to_commit = 0\n        res_token = None\n        if False: # MUTATION BYPASS: envelope check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_3_supervisor_envelope_enforcement_in_handle_propose"]
    },
    {
        "id": "MUTATION_30_REVOKED_PRIMARY_BYPASS",
        "name": "Bypass Active Device Multi-Sig Gate in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        if registry: # Devices have previously been registered\n            if not active_device_ids:",
        "replacement": "        if False: # MUTATION BYPASS: active device check disabled\n            if not active_device_ids:",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_5_enrollment_multi_sig_prevents_revoked_primary_bypass"]
    },
    {
        "id": "MUTATION_31_SESSION_BOUND_MULTISIG_BYPASS",
        "name": "Bypass Session-Bound V2 Multi-Sig Verification in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "                v2_msg = f\"ENROLL_DEVICE_V2|{session_id}|{device_id}|{public_key_pem.strip()}|{exp_val}\".encode('utf-8')\n                if not verify_asymmetric_signature(approver_entry[\"public_key\"], v2_msg, primary_approval_sig):",
        "replacement": "                v2_msg = f\"ENROLL_DEVICE_V2|{session_id}|{device_id}|{public_key_pem.strip()}|{exp_val}\".encode('utf-8')\n                if False: # MUTATION BYPASS: bypass asymmetric signature check",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_3_v1_fallback_eliminated_and_v2_strictly_verifies_signed_expiry"]
    },
    {
        "id": "MUTATION_32_GLOBAL_LOCKOUT_BYPASS",
        "name": "Bypass Global Persistent Lockout in start_local_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "    if is_enrollment_locked_out():\n        logger.warning(\"Enrollment blocked: Global pairing attempt lockout is active.\")\n        return \"\"",
        "replacement": "    if False: # MUTATION BYPASS: global lockout check disabled\n        pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_7_global_persistent_enrollment_lockout"]
    },
    {
        "id": "MUTATION_33_DOT_BOUNDARY_DOMAIN_BYPASS",
        "name": "Bypass Dot-Boundary Domain Scoping in is_domain_allowed",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": "    return c == a or c.endswith(\".\" + a)",
        "replacement": "    return c.endswith(a) # MUTATION BYPASS: allows fakebank.com to match bank.com",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch31_security_hardening.py::TestBatch31SecurityHardening::test_1_dot_boundary_domain_matching_in_policy_envelope"]
    },
    {
        "id": "MUTATION_34_ENROLLMENT_LOCKOUT_ENTRY_BYPASS",
        "name": "Bypass Global Lockout Check in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "    if is_enrollment_locked_out():\n        return False, \"DENY: Global enrollment lockout is active. Please wait or reset via console.\"",
        "replacement": "    if False: # MUTATION BYPASS: entry lockout check bypassed\n        pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch31_security_hardening.py::TestBatch31SecurityHardening::test_7_enrollment_lockout_enforced_in_complete_device_enrollment"]
    },
    {
        "id": "MUTATION_35_CONSOLE_RECOVERY_TOKEN_BYPASS",
        "name": "Bypass Console Recovery Token Verification in reset_pairing_lockout",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "    if not consume_console_recovery_token(recovery_token):",
        "replacement": "    if False and not consume_console_recovery_token(recovery_token): # MUTATION BYPASS: accept any arbitrary token",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_3_recovery_cli_non_interactive_fails_closed_and_sqlite_cross_process"]
    },
    {
        "id": "MUTATION_36_OUTCOME_UNKNOWN_EXCEPTION_BYPASS",
        "name": "Bypass UNKNOWN Outcome Classification on Exception in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                if execution_success:\n                    outcome_status = \"SUCCESS\"\n                elif exception_occurred:\n                    outcome_status = \"UNKNOWN\"",
        "replacement": "                if execution_success:\n                    outcome_status = \"SUCCESS\"\n                elif exception_occurred:\n                    outcome_status = \"FAILED\" # MUTATION BYPASS: misclassify exception as FAILED",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch31_security_hardening.py::TestBatch31SecurityHardening::test_10_audit_ledger_outcome_unknown_on_exception_and_locks_on_write_failure"]
    },
    {
        "id": "MUTATION_37_SUPERVISOR_DIRECT_APPROVAL_BYPASS",
        "name": "Bypass Supervisor Direct Approved Action Lookup in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                    current_epoch = taint_tracker.get_taint_epoch()\n                    if self.consume_approved_action(caller_id, tool, args_hash, current_epoch):",
        "replacement": "                    current_epoch = taint_tracker.get_taint_epoch()\n                    if False: # MUTATION BYPASS: disable direct internal approval lookup",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch31_security_hardening.py::TestBatch31SecurityHardening::test_11_supervisor_direct_internal_approval_lookup"]
    },
    {
        "id": "MUTATION_38_REVOKED_ALL_DEVICES_TOKEN_BYPASS",
        "name": "Bypass Recovery Token Requirement on All Devices Revoked in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "                if not consume_console_recovery_token(recovery_token):",
        "replacement": "                if False and not consume_console_recovery_token(recovery_token): # MUTATION BYPASS: allow unauthenticated enrollment when all devices are revoked",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_2_revoked_primary_recovery_fails_closed_without_token"]
    },
    {
        "id": "MUTATION_39_V2_SIGNED_EXPIRY_BYPASS",
        "name": "Bypass Signed Expiry Verification in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "                if exp_val < now:\n                    with _ENROLLMENT_LOCK:\n                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)\n                    return False, f\"APPROVAL_EXPIRED: Signed approval expired at {exp_val} (current time {now})\"",
        "replacement": "                if False: # MUTATION BYPASS: accept expired approval signature\n                    pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_3_v1_fallback_eliminated_and_v2_strictly_verifies_signed_expiry"]
    },
    {
        "id": "MUTATION_40_CLIENT_TOKEN_ENFORCEMENT_FAIL_CLOSED_BYPASS",
        "name": "Bypass Client Token Fail-Closed Requirement in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        if client_token_auth.is_token_enforcement_active() or client_token:\n            if not client_token:\n                return self._encode_reply(MSG_DECISION, {\n                    \"req_id\": req_id,\n                    \"status\": \"DENY\",\n                    \"reason_code\": REASON_UNAUTHORIZED_TOKEN,\n                    \"reason\": \"Missing client authentication token: Token enforcement is active\"\n                })",
        "replacement": "        if False: # MUTATION BYPASS: allow missing client token when enforcement active\n            pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_8_supervisor_client_token_enforcement_fails_closed"]
    },
    {
        "id": "MUTATION_41_POLICY_ENVELOPE_PROCESS_OMISSION_BYPASS",
        "name": "Bypass Policy Envelope Process Omission Check in check_boundary",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": "        if self.allowed_process_images:\n            if not current_process_image:\n                return False, f\"DENY: Missing target process image; envelope requires one of: {self.allowed_process_images}\", 0",
        "replacement": "        if self.allowed_process_images:\n            if False: # MUTATION BYPASS: permit omitted process image\n                pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_6_policy_envelope_fail_closed_omissions"]
    },
    {
        "id": "MUTATION_42_SUPERVISOR_INTENT_LEDGER_FAILURE_LOCK_BYPASS",
        "name": "Bypass Supervisor Lock on INTENT Audit Ledger Error in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "            except Exception as intent_err:\n                logger.critical(\"Audit ledger write failure during INTENT recording: %s\", intent_err)\n                self._transition_to_locked(f\"Audit ledger failure on INTENT: {intent_err}\")",
        "replacement": "            except Exception as intent_err:\n                pass # MUTATION BYPASS: ignore audit ledger failure and do not transition to locked",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_9_supervisor_locks_if_intent_ledger_fails"]
    },
    {
        "id": "MUTATION_43_APPROVAL_CACHE_CALLER_BINDING_BYPASS",
        "name": "Bypass Caller ID Binding in consume_approved_action",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        with self._approved_lock:\n            key = (caller_id, tool, args_hash.lower(), int(taint_epoch))\n            exp = self._approved_actions.pop(key, None)",
        "replacement": "        with self._approved_lock:\n            key = next((k for k in self._approved_actions if k[1] == tool and k[2] == args_hash.lower() and k[3] == int(taint_epoch)), None)\n            exp = self._approved_actions.pop(key, None) if key else None # MUTATION BYPASS: ignore caller_id",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch32_security_hardening.py::TestBatch32SecurityHardening::test_10_approval_cache_binds_caller_id_with_ttl"]
    },
    {
        "id": "MUTATION_44_POLICY_ENVELOPE_ENTER_KEY_DETECTION_BYPASS",
        "name": "Bypass Comprehensive Enter-to-Submit Form Check in check_boundary",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": "        if enter_detected:\n            return False, \"DENY: Keystroke contains Enter-to-submit form submission. Requires per-step step-up human approval.\", 0",
        "replacement": "        if False and enter_detected:\n            return False, \"DENY: Keystroke contains Enter-to-submit form submission. Requires per-step step-up human approval.\", 0",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch33_security_hardening.py::TestBatch33SecurityHardening::test_2_enter_to_submit_variations_detected"]
    },
    {
        "id": "MUTATION_45_APPROVAL_EXPIRY_STRICTLY_MANDATORY_BYPASS",
        "name": "Bypass Mandatory Signed approval_expiry in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "                if approval_expiry is None:\n                    with _ENROLLMENT_LOCK:\n                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)\n                    return False, \"APPROVAL_INVALID: Signed approval_expiry is strictly mandatory.\"",
        "replacement": "                if False and approval_expiry is None:\n                    with _ENROLLMENT_LOCK:\n                        _LOCAL_ENROLLMENT_SESSIONS.pop(session_id, None)\n                    return False, \"APPROVAL_INVALID: Signed approval_expiry is strictly mandatory.\"",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch33_security_hardening.py::TestBatch33SecurityHardening::test_1_approval_expiry_strictly_mandatory"]
    },
    {
        "id": "MUTATION_46_BROWSER_ENVELOPE_EMPTY_DOMAINS_BYPASS",
        "name": "Bypass Empty allowed_domains Fail-Closed Check in check_boundary",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": "        if is_browser_action:\n            if not self.allowed_domains:\n                return False, \"DENY: Browser envelope requires explicit non-empty allowed_domains\", 0",
        "replacement": "        if is_browser_action:\n            if False and not self.allowed_domains:\n                return False, \"DENY: Browser envelope requires explicit non-empty allowed_domains\", 0",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch33_security_hardening.py::TestBatch33SecurityHardening::test_4_browser_envelope_requires_non_empty_allowed_domains"]
    },
    {
        "id": "MUTATION_47_ENVELOPE_STEP_RESERVATION_RELEASE_BYPASS",
        "name": "Bypass Single-Point Step Reservation Release on Proposal Denial in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        finally:\n            # Single-point guaranteed reservation release for all early returns, denials, and exceptions.\n            # Release reservation ONLY if the actuator was NEVER invoked!\n            if res_token and not step_committed and not actuator_invoked:",
        "replacement": "        finally:\n            # Single-point guaranteed reservation release for all early returns, denials, and exceptions.\n            # Release reservation ONLY if the actuator was NEVER invoked!\n            if False and res_token and not step_committed and not actuator_invoked:",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_1_envelope_early_exit_paths_guarantee_zero_reserved_steps_and_no_unbound_local"]
    },
    {
        "id": "MUTATION_48_KEYCODE_13_ENTER_BYPASS",
        "name": "Bypass Numeric Keycode 13 Enter-to-Submit Detection in canonicalize_keyboard_arguments",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "                if vk in (13, 0x0D):\n                    enter_detected = True",
        "replacement": "                if False and vk in (13, 0x0D):\n                    enter_detected = True",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_4_exact_vk_canonicalization_and_actuator_enforcement"]
    },
    {
        "id": "MUTATION_49_SYNTHETIC_CTRL_ALT_P_BYPASS",
        "name": "Bypass Synthetic Ctrl+Alt+P Injection Prevention in check_boundary",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": "        # Physical console enrollment hotkey (Ctrl + Alt + P) can NEVER be synthesized\n        if ctrl_alt_p_detected:\n            return False, \"DENY: Synthetic simulation of physical console pairing hotkey (Ctrl+Alt+P) is strictly prohibited.\", 0",
        "replacement": "        # Physical console enrollment hotkey (Ctrl + Alt + P) can NEVER be synthesized\n        if False and ctrl_alt_p_detected:\n            return False, \"DENY: Synthetic simulation of physical console pairing hotkey (Ctrl+Alt+P) is strictly prohibited.\", 0",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch34_security_hardening.py::TestBatch34SecurityHardening::test_5_synthetic_ctrl_alt_p_rejected"]
    },
    {
        "id": "MUTATION_50_ATOMIC_SESSION_POP_BYPASS",
        "name": "Bypass Atomic Session Deletion on Code Match in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        # Atomically consume session from registry the instant pairing code matches (TOCTOU elimination)\n        del _LOCAL_ENROLLMENT_SESSIONS[session_id]",
        "replacement": "        # MUTATION BYPASS: delay session deletion allowing replay/race\n        pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch34_security_hardening.py::TestBatch34SecurityHardening::test_4_concurrent_session_reuse_blocked_by_atomic_pop"]
    },
    {
        "id": "MUTATION_51_UNKNOWN_OUTCOME_STEP_CONSUMPTION_BYPASS",
        "name": "Bypass Step Budget Consumption on Actuator Invocation / UNKNOWN Outcomes in _handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "            if actuator_invoked:\n                if getattr(self, \"envelope\", None) and getattr(self.envelope, \"is_active\", False):\n                    self.envelope.commit_step(ks_to_commit, res_token)\n                    step_committed = True",
        "replacement": "            if False and actuator_invoked:\n                if getattr(self, \"envelope\", None) and getattr(self.envelope, \"is_active\", False):\n                    self.envelope.commit_step(ks_to_commit, res_token)\n                    step_committed = True",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch35_security_hardening.py::TestBatch35SecurityHardening::test_3_unknown_outcome_consumes_step_budget"]
    },
    {
        "id": "MUTATION_52_PRODUCTION_APPROVAL_RELAY_BYPASS",
        "name": "Bypass Phone Approval Relay to Supervisor Cache in verify_action_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        helm_supervisor.record_approved_action(\n            caller_id=target_caller,\n            tool=expected_action,\n            args_hash=str(expected_payload_hash).lower(),\n            taint_epoch=approval_epoch,\n            ttl=min(remaining_ttl, 120.0),\n            signed_blob=signed_approval_blob\n        )",
        "replacement": "        pass # MUTATION BYPASS: drop approval relay to supervisor",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch35_security_hardening.py::TestBatch35SecurityHardening::test_4_production_approval_relay_to_supervisor_cache_and_db"]
    },
    {
        "id": "MUTATION_53_PUBLISHER_KEY_SHA256_FINGERPRINT_PINNING_BYPASS",
        "name": "Bypass Publisher Public Key SPKI DER SHA-256 Fingerprint Check in update_verifier.py",
        "file": os.path.join(BASE_DIR, "update_verifier.py"),
        "target": "assert get_publisher_key_der_hash() == PINNED_PUBLISHER_KEY_SHA256, \"Publisher key integrity violation: SHA256 mismatch!\"",
        "replacement": "# MUTATION BYPASS: drop key fingerprint assertion\npass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch35_security_hardening.py::TestBatch35SecurityHardening::test_1_pinned_publisher_key_der_sha256_fingerprint"]
    },
    {
        "id": "MUTATION_54_CONSOLE_RECOVERY_TOKEN_TTY_CHECK_BYPASS",
        "name": "Bypass Console Presence Verification in helm.py --pairing-unlock",
        "file": os.path.join(BASE_DIR, "helm.py"),
        "target": "        if not sys.stdin.isatty():\n            print(\"✗ [HELM SECURITY] Interactive console presence required to unlock pairing.\")\n            return",
        "replacement": "        if False and not sys.stdin.isatty():\n            pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_3_recovery_cli_non_interactive_fails_closed_and_sqlite_cross_process"]
    },
    {
        "id": "MUTATION_55_TELEGRAM_MEDIATION_BROKER_BYPASS",
        "name": "Bypass ActionBroker Complete Mediation in Telegram Bridge Callback",
        "file": os.path.join(BASE_DIR, "telegram_bridge.py"),
        "target": "            ok, msg, _ = action_broker.execute_action('helm_control_media', {'action': 'play_pause'}, caller_id='telegram_remote')",
        "replacement": "            ok, msg = windows_tools.control_media('play_pause') # MUTATION BYPASS: bypass action_broker",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_entry_point_enumeration.py::TestEntryPointEnumeration::test_1_telegram_callback_entry_points_dispatch_via_broker"]
    },
    {
        "id": "MUTATION_56_ACTUATOR_INVOKED_PRE_TRY_INIT_BYPASS",
        "name": "Bypass Pre-Try actuator_invoked Initialization in PolicySupervisor._handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        step_committed = False\n        actuator_invoked = False\n        try:",
        "replacement": "        step_committed = False\n        # MUTATION BYPASS: drop actuator_invoked pre-init causing UnboundLocalError\n        try:",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_1_envelope_early_exit_paths_guarantee_zero_reserved_steps_and_no_unbound_local"]
    },
    {
        "id": "MUTATION_57_DEVICE_APPROVAL_SUPERVISOR_RELAY_BYPASS",
        "name": "Bypass Phone Device Approval Relay to Supervisor Cache in verify_device_approval",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        helm_supervisor.record_approved_action(\n            caller_id=target_caller,\n            tool=item[\"tool_name\"],\n            args_hash=str(item[\"args_hash\"]).lower(),\n            taint_epoch=item.get(\"taint_epoch\", 0),\n            ttl=min(remaining_ttl, 120.0),\n            signed_blob=signed_approval_blob\n        )",
        "replacement": "        pass # MUTATION BYPASS: drop device approval relay to supervisor",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_2_verify_device_approval_relays_to_supervisor_cache_and_db"]
    },
    {
        "id": "MUTATION_58_RECOVERY_TOKEN_CROSS_PROCESS_SQLITE_BYPASS",
        "name": "Bypass Recovery Token Cross-Process SQLite Consumption in consume_console_recovery_token",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": '        with db_utils.get_db() as conn:\n            cursor = conn.execute(\n                "UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0 AND expires_at > ?",\n                (tok_hash, now)\n            )',
        "replacement": '        with db_utils.get_db() as conn:\n            cursor = conn.execute(\n                "UPDATE console_recovery_tokens SET consumed = 0 WHERE token_hash = ? AND consumed = 0 AND expires_at > ?",\n                (tok_hash, now)\n            ) # MUTATION BYPASS: don\'t mark consumed',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_5_recovery_token_single_use_via_authoritative_db_record"]
    },
    {
        "id": "MUTATION_59_EXACT_VK_CHORD_DETECTION_BYPASS",
        "name": "Bypass Exact Virtual-Key Code Chord Matching in canonicalize_keyboard_arguments",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "    has_ctrl = any(vk in detected_vks for vk in (17, 162, 163))\n    has_alt = any(vk in detected_vks for vk in (18, 164, 165))\n    has_p = (80 in detected_vks)",
        "replacement": "    has_ctrl = False # MUTATION BYPASS: bypass VK chord detection\n    has_alt = False\n    has_p = False",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_4_exact_vk_canonicalization_and_actuator_enforcement"]
    },
    {
        "id": "MUTATION_60_SUPERVISOR_FIRST_FOREGROUND_RESOLUTION_BYPASS",
        "name": "Bypass Supervisor-First Foreground Process Resolution in PolicySupervisor._handle_propose",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        current_proc = supervisor_proc  # Fail-closed: Supervisor inspects OS foreground; NEVER accepts worker self-attested proc",
        "replacement": "        current_proc = args.get(\"target_process\") or supervisor_proc # MUTATION BYPASS: trust worker proc",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch36_security_hardening.py::TestBatch36SecurityHardening::test_5_supervisor_first_foreground_and_uia_domain_scoping"]
    },
    {
        "id": "MUTATION_61_SIGNED_APPROVAL_EVIDENCE_BYPASS",
        "name": "Bypass Signed Approval Blob Cryptographic Verification in consume_approved_action",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                    if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):",
        "replacement": "                    if True: # MUTATION BYPASS: accept unsigned or forged evidence",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch37_security_hardening.py::TestBatch37SecurityHardening::test_1_signed_approval_evidence_verification_and_unverified_sqlite_row_rejection"]
    },
    {
        "id": "MUTATION_62_UIA_TOP_LEVEL_WINDOW_CONSTRAINT_BYPASS",
        "name": "Bypass Top-Level Window Handle Scoping in get_browser_active_domain",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "        if edit and edit.Exists(0.01):",
        "replacement": "        if not edit:\n            edit = uia.EditControl(searchDepth=6, SubName=\"Address\") # MUTATION BYPASS: query root desktop\n        if edit and edit.Exists(0.01):",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch37_security_hardening.py::TestBatch37SecurityHardening::test_3_uia_domain_resolution_strictly_scoped_to_hwnd_descendants"]
    },
    {
        "id": "MUTATION_63_TOCTOU_ACTUATOR_FOREGROUND_PROCESS_BYPASS",
        "name": "Bypass TOCTOU Foreground Process Re-Resolution in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        if tool in UI_INTERACTIVE_TOOLS:",
        "replacement": "        if False and tool in UI_INTERACTIVE_TOOLS: # MUTATION BYPASS: ignore TOCTOU",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch37_security_hardening.py::TestBatch37SecurityHardening::test_4_actuator_toctou_defense_blocks_foreground_window_switching"]
    },
    {
        "id": "MUTATION_64_SYSTEM_HOTKEY_CHORD_BLOCK_BYPASS",
        "name": "Bypass Dangerous System Hotkey Chord Detection in detect_blocked_system_chords",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "    if has_alt and has_f4:\n        return \"Alt+F4\"",
        "replacement": "    if False and has_alt and has_f4: # MUTATION BYPASS: allow Alt+F4\n        return \"Alt+F4\"",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch37_security_hardening.py::TestBatch37SecurityHardening::test_5_exact_vk_canonicalizer_ignores_numeric_prose_and_blocks_dangerous_system_chords"]
    },
    {
        "id": "MUTATION_65_RECOVERY_CLI_UAC_ELEVATION_CHECK_BYPASS",
        "name": "Bypass Windows UAC Administrative Elevation Check in helm.py --pairing-unlock",
        "file": os.path.join(BASE_DIR, "helm.py"),
        "target": "        if not is_admin:\n            print(\"✗ [HELM SECURITY] Administrative elevation required.\")",
        "replacement": "        if False and not is_admin: # MUTATION BYPASS: allow standard non-elevated user\n            print(\"✗ [HELM SECURITY] Administrative elevation required.\")",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch37_security_hardening.py::TestBatch37SecurityHardening::test_2_recovery_cli_requires_uac_secure_desktop_elevation"]
    },
    {
        "id": "MUTATION_66_ANTI_BURN_DOS_SQLITE_LOOP_BYPASS",
        "name": "Revert SQLite Approval Consumption to Single-Row (Anti-Burn DoS Bypass)",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                for row in rows:\n                    sig_blob = row[\"signature_blob\"] if \"signature_blob\" in row.keys() else row[1]",
        "replacement": "                for row in rows:\n                    break # MUTATION BYPASS: burn immediately without iterating candidate rows\n                    sig_blob = row[\"signature_blob\"] if \"signature_blob\" in row.keys() else row[1]",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch38_security_hardening.py::TestBatch38SecurityHardening::test_3_anti_burn_dos_junk_row_defense"]
    },
    {
        "id": "MUTATION_67_CHALLENGE_V3_RECOMPUTED_HASH_BYPASS",
        "name": "Blindly Trust Blob challenge_hash Without Recomputing from Fields",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "        if blob.get(\"challenge_hash\") and blob.get(\"challenge_hash\") != expected_hash:\n            return False\n        data_to_verify = expected_hash.encode('utf-8')",
        "replacement": "        # MUTATION BYPASS: blindly trust blob challenge_hash\n        data_to_verify = (blob.get(\"challenge_hash\") or expected_hash).encode('utf-8')",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch38_security_hardening.py::TestBatch38SecurityHardening::test_2_tampered_challenge_fields_rejected_even_if_hash_signed"]
    },
    {
        "id": "MUTATION_68_CHALLENGE_V3_CALLER_BINDING_BYPASS",
        "name": "Omit caller_id from CHALLENGE_V3 Canonical Raw String in generate_approval_challenge",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        raw_challenge = f\"CHALLENGE_V3|{device_id}|{caller_id}|{tool_name}|{args_hash}|{nonce}|{expiry}|{taint_epoch}|{challenge_seq}\"",
        "replacement": "        raw_challenge = f\"CHALLENGE_V3|{device_id}|omitted|{tool_name}|{args_hash}|{nonce}|{expiry}|{taint_epoch}|{challenge_seq}\"",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch38_security_hardening.py::TestBatch38SecurityHardening::test_1_challenge_v3_cryptographic_caller_binding"]
    },
    {
        "id": "MUTATION_69_PERSISTENT_NONCE_CONSUMPTION_BYPASS",
        "name": "Bypass Persistent Nonce Check in Supervisor consume_approved_action",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):\n                            logger.warning(\"SQLite approved action row %s rejected: nonce already consumed (replay)!\", row[\"id\"])",
        "replacement": "                        if False and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp): # MUTATION BYPASS: allow replay\n                            logger.warning(\"SQLite approved action row %s rejected: nonce already consumed (replay)!\", row[\"id\"])",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch38_security_hardening.py::TestBatch38SecurityHardening::test_4_sqlite_row_replay_rejected_by_persistent_nonce_store"]
    },
    {
        "id": "MUTATION_70_TOTAL_WIN_KEY_CHORD_DENIAL_BYPASS",
        "name": "Bypass Total Win-Key Chord Denial in windows_tools.py",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "        if other_vks or sub_tokens:\n            tok_name = sorted(sub_tokens)[0].upper() if sub_tokens else (chr(other_vks[0]).upper() if 32 <= other_vks[0] <= 126 else str(other_vks[0]))\n            return f\"Win+{tok_name}\"",
        "replacement": "        if False and (other_vks or sub_tokens): # MUTATION BYPASS: permit Win-key chords\n            tok_name = sorted(sub_tokens)[0].upper() if sub_tokens else (chr(other_vks[0]).upper() if 32 <= other_vks[0] <= 126 else str(other_vks[0]))\n            return f\"Win+{tok_name}\"",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch38_security_hardening.py::TestBatch38SecurityHardening::test_5_total_win_key_and_dangerous_chord_denial"]
    },
    {
        "id": "MUTATION_71_POINT_UNDER_CURSOR_BYPASS",
        "name": "Bypass WindowFromPoint Point-Under-Cursor Self-Targeting Defense in helm_supervisor.py",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "            if target_x is not None and target_y is not None:",
        "replacement": "            if False and target_x is not None and target_y is not None: # MUTATION BYPASS: allow point-under-cursor click on Helm UI\n                pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch39_security_hardening.py::TestBatch39SecurityHardening::test_1_point_under_cursor_windowfrompoint_self_targeting_defense"]
    },
    {
        "id": "MUTATION_72_LONE_WIN_KEY_DENIAL_BYPASS",
        "name": "Bypass Lone Win-Key Denial in detect_blocked_system_chords",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "        # Lone Win key denial: blocks opening Start menu / search launch vectors\n        return \"Win\"",
        "replacement": "        # MUTATION BYPASS: allow lone Win key\n        return None",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch39_security_hardening.py::TestBatch39SecurityHardening::test_2_lone_win_key_denial"]
    },
    {
        "id": "MUTATION_73_CHORD_EXACT_ATOMIC_TOKEN_BYPASS",
        "name": "Bypass Exact Atomic Token Chord Detection in windows_tools.py",
        "file": os.path.join(BASE_DIR, "windows_tools.py"),
        "target": "    has_tab = (9 in detected_vks) or (\"tab\" in atomic_tokens)",
        "replacement": "    has_tab = False # MUTATION BYPASS: never detect tab key",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch39_security_hardening.py::TestBatch39SecurityHardening::test_3_exact_token_matching_without_substring_ambiguity"]
    },
    {
        "id": "MUTATION_74_RECOVERY_TOKEN_UNLINK_FAIL_CLOSED_BYPASS",
        "name": "Swallow Unlink Failure in consume_admin_recovery_token (Multi-Use Replay Bypass)",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        except Exception as rm_err:\n            logger.critical(\"Failed to unlink admin recovery token; single use invariant failed: %s\", rm_err)\n            return False",
        "replacement": "        except Exception as rm_err: # MUTATION BYPASS: return True on unlink failure\n            return True",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch39_security_hardening.py::TestBatch39SecurityHardening::test_4_recovery_token_single_use_unlink_failure_fails_closed"]
    },
    {
        "id": "MUTATION_75_COMPILED_IN_SAFETY_FLOOR_BYPASS",
        "name": "Bypass Compiled-In Consequential Safety Floor in is_confirmation_required",
        "file": os.path.join(BASE_DIR, "rails_config.py"),
        "target": "        if canonical in COMPILED_IN_CONSEQUENTIAL_TOOLS or tool_name in COMPILED_IN_CONSEQUENTIAL_TOOLS:\n            return True",
        "replacement": "        if False: # MUTATION BYPASS: bypass compiled-in floor and permit weakened disk config\n            return True",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch39_security_hardening.py::TestBatch39SecurityHardening::test_5_compiled_in_safety_floor_covers_all_consequential_and_fact_tools"]
    },
    {
        "id": "MUTATION_76_PHONE_SIGNATURE_MANDATORY_BYPASS",
        "name": "Bypass Mandatory Mobile Signature Check When Hardware Device Is Enrolled",
        "file": os.path.join(BASE_DIR, "rails_confirmation.py"),
        "target": "                if not signed_evidence:\n                    return False, \"DENIED: Action confirmation strictly requires verified out-of-band signature from enrolled mobile device.\", None",
        "replacement": "                if False and not signed_evidence: # MUTATION BYPASS: make mobile signature optional\n                    pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch41_security_hardening.py::TestBatch41SecurityHardening::test_1_verified_mobile_signature_strictly_required_when_device_enrolled"]
    },
    {
        "id": "MUTATION_77_ZERO_TRUST_NO_DEVICE_BYPASS",
        "name": "Bypass Zero-Trust No-Device Consequential Action Denial in rails_confirmation.py",
        "file": os.path.join(BASE_DIR, "rails_confirmation.py"),
        "target": '                return False, "DENIED: No mobile device enrolled. All consequential tools strictly require approval from an enrolled phone.", None',
        "replacement": '                pass  # MUTATION BYPASS: allow confirmation without enrolled phone',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_rails_safety.py::test_consequential_action_stops_and_requires_confirmation"]
    },
    {
        "id": "MUTATION_78_SUPERVISOR_PIPE_FAIL_CLOSED_BYPASS",
        "name": "Bypass Out-of-Process Pipe Client Fail-Closed Behavior on Supervisor Death",
        "file": os.path.join(BASE_DIR, "action_broker.py"),
        "target": "                        return False, \"Security Gate: Supervisor process is unreachable or disconnected (fail-closed).\", None",
        "replacement": "                        return True, \"MUTATION BYPASS: allow execution without supervisor\", None",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch41_security_hardening.py::TestBatch41SecurityHardening::test_3_supervisor_killed_all_channels_fail_closed"]
    },
    {
        "id": "MUTATION_79_BASE_DIR_PROCESS_IMAGE_BYPASS",
        "name": "Bypass WindowFromPoint Application Image (BASE_DIR) Detection in helm_supervisor.py",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": "                            if os.path.commonpath([cand, base]) == base:\n                                raise CompleteMediationBreachError(",
        "replacement": "                            if False and os.path.commonpath([cand, base]) == base: # MUTATION BYPASS\n                                raise CompleteMediationBreachError(",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch41_security_hardening.py::TestBatch41SecurityHardening::test_6_windowfrompoint_detects_helm_by_process_path"]
    },
    {
        "id": "MUTATION_80_RECOVERY_TOKEN_DELETE_DACL_DOS_BYPASS",
        "name": "Reintroduce Unelevated DELETE Permission on Admin Recovery Token in phone_approval_portal.py",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ, users_sid)",
        "replacement": "            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ | win32con.DELETE, users_sid) # MUTATION BYPASS: reintroduce unelevated DoS deletion",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch41_security_hardening.py::TestBatch41SecurityHardening::test_5_recovery_token_dacl_denies_unelevated_delete"]
    },
    {
        "id": "MUTATION_81_SAFETY_FLOOR_FACT_TOOLS_BYPASS",
        "name": "Remove helm_remember_fact from COMPILED_IN_CONSEQUENTIAL_TOOLS in rails_config.py",
        "file": os.path.join(BASE_DIR, "rails_config.py"),
        "target": '    "helm_remember_fact",',
        "replacement": '    # "helm_remember_fact", # MUTATION BYPASS: drop consequential protection',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_1_compiled_in_consequential_tools_floor_covers_all_non_readonly"]
    },
    {
        "id": "MUTATION_82_DEVICE_REGISTRY_FAIL_OPEN_BYPASS",
        "name": "Bypass Fail-Closed Device Registry Exception Handling in rails_confirmation.py",
        "file": os.path.join(BASE_DIR, "rails_confirmation.py"),
        "target": '                return False, f"DENIED: Device registry unavailable or corrupted (fail-closed): {reg_err}", None',
        "replacement": '                devices = {} # MUTATION BYPASS: fail open on registry corruption',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_3_device_registry_failure_fails_closed"]
    },
    {
        "id": "MUTATION_83_UIA_DOMAIN_RESOLUTION_FALLBACK_BYPASS",
        "name": "Bypass UIA Browser Domain Resolution Fail-Closed in PolicyEnvelope.reserve_step",
        "file": os.path.join(BASE_DIR, "policy_envelope.py"),
        "target": '            if not current_domain:\n                return False, "DENY: Browser domain could not be verified via UIA (fail-closed)", 0',
        "replacement": '            if not current_domain:\n                pass # MUTATION BYPASS: allow None domain without fail-closed rejection',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_4_browser_domain_uia_failure_fails_closed"]
    },
    {
        "id": "MUTATION_84_OUTBOUND_SSRF_PROTECTION_BYPASS",
        "name": "Bypass Outbound SSRF Protection Gate in action_broker.py",
        "file": os.path.join(BASE_DIR, "action_broker.py"),
        "target": '                ssrf_err = helm_ssrf.check_ssrf(cand_url)',
        "replacement": '                ssrf_err = None # MUTATION BYPASS: allow SSRF to internal/cloud metadata',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_4_action_broker_blocks_action_with_ssrf_url"]
    },
    {
        "id": "MUTATION_85_CREDENTIAL_STRIPPER_REDACTION_BYPASS",
        "name": "Bypass Secret and Credential Redaction in agent_tools.py",
        "file": os.path.join(BASE_DIR, "agent_tools.py"),
        "target": '        result = helm_credential_stripper.redact_secrets(result)',
        "replacement": '        pass # MUTATION BYPASS: allow credentials to leak into logs and model context',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_6_tool_registry_redacts_secrets_from_results"]
    },
    {
        "id": "MUTATION_86_CONFIRM_CLIENT_PID_ROLE_BYPASS",
        "name": "Bypass Kernel-Attested Client PID Role Check in _handle_confirm",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": '            if not self.is_ui_pid_valid(client_pid):',
        "replacement": '            if False: # MUTATION BYPASS: allow unregistered PID to confirm',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_6_supervisor_named_pipe_confirm_and_taint_query"]
    },
    {
        "id": "MUTATION_87_CONFIRM_ZERO_TRUST_NO_DEVICE_BYPASS",
        "name": "Bypass Zero-Trust No-Device Denial in helm_supervisor._handle_confirm",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": """            return self._encode_reply(MSG_DECISION, {
                "status": "DENY",
                "reason_code": REASON_UNAUTHORIZED_TOKEN,
                "reason": "DENIED: No mobile device enrolled. All consequential tools strictly require approval from an enrolled phone."
            })""",
        "replacement": '            pass  # MUTATION BYPASS: accept confirmation without enrolled phone',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_6_supervisor_named_pipe_confirm_and_taint_query"]
    },
    {
        "id": "MUTATION_88_NONCE_ANTI_REPLAY_BYPASS",
        "name": "Bypass Anti-Replay Nonce Check in verify_signed_approval_evidence",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": '        if not device_registry.check_and_record_consumed_nonce(str(nonce), expiry):',
        "replacement": '        if False: # MUTATION BYPASS: allow replayed nonces to mint unlimited tokens',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_6_supervisor_named_pipe_confirm_and_taint_query"]
    },
    {
        "id": "MUTATION_89_DEVICE_REGISTRY_TAMPERING_DETECTION_BYPASS",
        "name": "Bypass Device Registry Deletion Tamper Detection in _load_device_registry",
        "file": os.path.join(BASE_DIR, "device_registry.py"),
        "target": '    if not os.path.exists(DEVICE_REGISTRY_PATH):\n        if has_marker:',
        "replacement": '    if not os.path.exists(DEVICE_REGISTRY_PATH):\n        if False: # MUTATION BYPASS: ignore deleted registry',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_8_device_registry_tampering_or_deletion_fails_closed"]
    },
    {
        "id": "MUTATION_90_SSRF_RESOLVE_AND_PIN_ALL_RECORDS_BYPASS",
        "name": "Bypass All-Records A/AAAA Validation in helm_ssrf.resolve_and_pin_ip",
        "file": os.path.join(BASE_DIR, "helm_ssrf.py"),
        "target": '        if is_private_ip(ip):\n            return False, f"SSRF violation: resolved to private or reserved IP {ip}", None',
        "replacement": '        if False and is_private_ip(ip): # MUTATION BYPASS: ignore private IP in multi-homed DNS\n            pass',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_12_ssrf_resolve_and_pin_validates_all_records"]
    },
    {
        "id": "MUTATION_91_SESSION_COMPRESSION_TAINT_INHERITANCE_BYPASS",
        "name": "Bypass Origin Metadata Taint Inheritance in helm_session_compression.py",
        "file": os.path.join(BASE_DIR, "helm_session_compression.py"),
        "target": '            if src in UNTRUSTED_MESSAGE_ORIGINS or m.get("role") in ("tool", "system_external"):',
        "replacement": '            if False: # MUTATION BYPASS: ignore untrusted message origin metadata',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_9_context_compression_taint_inheritance_and_nonce_wrapping"]
    },
    {
        "id": "MUTATION_92_MSG_CREATE_CONFIRM_REQUEST_ROLE_BYPASS",
        "name": "Bypass Attested UI PID Check in _handle_create_confirm_request",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": '        if client_pid is not None and not self.is_ui_pid_valid(client_pid):',
        "replacement": '        if False: # MUTATION BYPASS: allow un-attested process to create authoritative requests',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_9_two_process_confirmation_request_creation_and_gesture_verification"]
    },
    {
        "id": "MUTATION_93_REGISTER_UI_INDEPENDENT_IDENTITY_BYPASS",
        "name": "Bypass Kernel Child and Session Token Attestation in _handle_register_ui",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": '            if not (is_authorized_child or has_valid_token):',
        "replacement": '            if False: # MUTATION BYPASS: allow arbitrary scripts without token or child status',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_11_unauthorized_process_cannot_register_as_ui"]
    },
    {
        "id": "MUTATION_94_DEVICE_REGISTRY_WINREG_TAMPER_DETECTION_BYPASS",
        "name": "Bypass Windows Registry Enrollment Check in _load_device_registry",
        "file": os.path.join(BASE_DIR, "device_registry.py"),
        "target": '    has_marker = os.path.exists(DEVICE_ENROLLED_MARKER) or _check_windows_registry_marker() or _EVER_ENROLLED',
        "replacement": '    has_marker = os.path.exists(DEVICE_ENROLLED_MARKER) # MUTATION BYPASS: omit Windows registry check',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_10_device_registry_tampering_fails_closed_across_windows_registry"]
    },
    {
        "id": "MUTATION_95_MCP_TOOL_HTTP_FETCH_SSRF_BYPASS",
        "name": "Bypass SSRF Validation in helm_http_fetch Tool",
        "file": os.path.join(BASE_DIR, "helm_mcp.py"),
        "target": '            ok_f, code_f, body_f = helm_ssrf.pinned_fetch(u, method=m, headers=hdrs, timeout_sec=tmo)',
        "replacement": '            ok_f, code_f, body_f = True, 200, "MUTATION_LEAK" # MUTATION BYPASS: ignore SSRF check',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_12_helm_http_fetch_pinned_egress_and_taint"]
    },
    {
        "id": "MUTATION_96_MEETING_NOTES_PROVENANCE_TAINT_BYPASS",
        "name": "Omit returns_untrusted from helm_get_meeting_notes in MCP_TOOLS",
        "file": os.path.join(BASE_DIR, "helm_mcp.py"),
        "target": '        "name": "helm_get_meeting_notes",\n        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI loopback.",\n        "capabilityTier": "READ_ONLY",\n        "returns_untrusted": True,',
        "replacement": '        "name": "helm_get_meeting_notes",\n        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI loopback.",\n        "capabilityTier": "READ_ONLY", # MUTATION BYPASS: omit returns_untrusted',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch43_security_hardening.py::TestBatch43SecurityHardening::test_12_helm_http_fetch_pinned_egress_and_taint"]
    },
    {
        "id": "MUTATION_97_LOCAL_HARDWARE_RECOMMENDATION_BYPASS",
        "name": "Bypass Local Hardware Inference Tier Recommendation in helm_hardware_profiler.py",
        "file": os.path.join(BASE_DIR, "helm_hardware_profiler.py"),
        "target": '        if has_ollama and vram >= 6000:',
        "replacement": '        if False and has_ollama and vram >= 6000: # MUTATION BYPASS: disable local GPU inference tier',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_14_hardware_profiler_runtime_recommendation"]
    },
    {
        "id": "MUTATION_98_RESOURCE_BUDGET_CIRCUIT_BREAKER_BYPASS",
        "name": "Bypass Dollar Budget Circuit Breaker in helm_resource_tracker.py",
        "file": os.path.join(BASE_DIR, "helm_resource_tracker.py"),
        "target": '        budget_exceeded = self._daily_spend > self.daily_budget_usd',
        "replacement": '        budget_exceeded = False # MUTATION BYPASS: disable budget circuit breaker',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_openjarvis_integration.py::TestOpenJarvisIntegration::test_16_resource_tracker_budget_circuit_breaker"]
    },
    {
        "id": "MUTATION_99_FOREGROUND_WINDOW_MISSING_PROC_FAIL_CLOSED_BYPASS",
        "name": "Bypass Foreground Window Missing Proc/PID Fail-Closed Check in helm_supervisor.py",
        "file": os.path.join(BASE_DIR, "helm_supervisor.py"),
        "target": '            if not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name"):',
        "replacement": '            if False and (not fg_act or not fg_act.get("pid") or not fg_act.get("proc_name")): # MUTATION BYPASS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_tier_a_adversarial.py::TestTierAAdversarialSuite::test_6_actuator_denies_when_foreground_missing_proc_name_or_pid"]
    },
    {
        "id": "MUTATION_100_OWNER_RIGHTS_ACE_DROP",
        "name": "Drop OWNER RIGHTS ACE (S-1-3-4) in helm_confinement.py",
        "file": os.path.join(BASE_DIR, "helm_confinement.py"),
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
        "name": "Leak Raw Email Body into Planner Schema in helm_quarantine_reader.py",
        "file": os.path.join(BASE_DIR, "helm_quarantine_reader.py"),
        "target": '        body_handle = self.handle_store.store(body, prefix="EMAIL")',
        "replacement": '        body_handle = self.handle_store.store(body, prefix="EMAIL")\n        schema["raw_body_leak"] = body # MUTATION LEAK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_tier_a_adversarial.py::TestTierAAdversarialSuite::test_1_adversarial_email_injection_zero_tool_call"]
    },
    {
        "id": "MUTATION_104_STRUCTURED_APPROVAL_BIDI_BYPASS",
        "name": "Bypass Prohibited Bidi/Zero-Width Characters Check in helm_structured_approval.py",
        "file": os.path.join(BASE_DIR, "helm_structured_approval.py"),
        "target": '        if cp in PROHIBITED_CODEPOINTS:',
        "replacement": '        if False: # MUTATION BYPASS PROHIBITED_CODEPOINTS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_structured_approval.py::TestStructuredApprovals::test_2_prohibits_bidi_override_characters"]
    },
    {
        "id": "MUTATION_105_BROWSER_BROKER_TOCTOU_BYPASS",
        "name": "Bypass DOM Mutation Anti-TOCTOU Check in helm_browser_broker.py",
        "file": os.path.join(BASE_DIR, "helm_browser_broker.py"),
        "target": '        if current_snap.snapshot_hash != prior_snapshot.snapshot_hash:',
        "replacement": '        if False: # MUTATION BYPASS DOM TOCTOU CHECK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_browser_broker.py::TestBrowserBroker::test_5_form_submission_anti_toctou_defense"]
    },
    {
        "id": "MUTATION_106_PLAN_ENVELOPE_TAINT_BYPASS",
        "name": "Bypass Plan Envelope Unexpected Taint Invalidation in helm_plan_envelopes.py",
        "file": os.path.join(BASE_DIR, "helm_plan_envelopes.py"),
        "target": '        if unexpected_taint_detected or current_taint_epoch > self.plan.taint_epoch:',
        "replacement": '        if False: # MUTATION BYPASS UNEXPECTED TAINT CHECK',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_plan_envelopes.py::TestPlanEnvelopes::test_4_unexpected_taint_invalidates_plan"]
    },
    {
        "id": "MUTATION_107_WEBAUTHN_UV_BYPASS",
        "name": "Bypass WebAuthn User Verification (UV) Requirement in webauthn_verifier.py",
        "file": os.path.join(BASE_DIR, "webauthn_verifier.py"),
        "target": '    if rp.require_uv and not ad.flags & FLAG_UV:',
        "replacement": '    if False: # MUTATION_107_BYPASS_UV',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_webauthn_verifier.TestWebAuthnVerifier.test_6_user_presence_and_verification_enforced"]
    },
    {
        "id": "MUTATION_108_WEBAUTHN_SYNCED_PASSKEY_BE_BYPASS",
        "name": "Bypass Device-Bound Backup-Eligible Rejection in webauthn_verifier.py",
        "file": os.path.join(BASE_DIR, "webauthn_verifier.py"),
        "target": '    if rp.require_device_bound and be:',
        "replacement": '    if False: # MUTATION_108_BYPASS_BE',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_webauthn_verifier.TestWebAuthnVerifier.test_7_synced_passkey_backup_eligible_rejected"]
    },
    {
        "id": "MUTATION_109_WEBAUTHN_SIGN_COUNT_ROLLBACK_BYPASS",
        "name": "Bypass Monotonic Sign Counter Rollback Detection in webauthn_verifier.py",
        "file": os.path.join(BASE_DIR, "webauthn_verifier.py"),
        "target": '        if ad.sign_count <= cred.sign_count:',
        "replacement": '        if False: # MUTATION_109_BYPASS_SIGN_COUNT_ROLLBACK',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_webauthn_verifier.TestWebAuthnVerifier.test_8_sign_count_rollback_detected"]
    },
    {
        "id": "MUTATION_110_INJECTION_BASELINE_ZERO_POLICY_ASR_BYPASS",
        "name": "Bypass Complete Mediation Gating in injection_baseline_harness.py",
        "file": os.path.join(BASE_DIR, "injection_baseline_harness.py"),
        "target": '                return "DENIED", f"Supervisor complete mediation blocked tool {tool}"',
        "replacement": '                return "ALLOWED", "MUTATION_110_BYPASS_MEDIATION"',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_injection_baseline_harness.TestInjectionBaselineHarness.test_3_zero_policy_asr_invariant"]
    },
    {
        "id": "MUTATION_111_MAIL_SEND_WEBAUTHN_BYPASS",
        "name": "Bypass WebAuthn Assertion Check in MailConnector.send",
        "file": os.path.join(BASE_DIR, "helm_mail_calendar.py"),
        "target": '        webauthn_verifier.verify_assertion(rp, cred, assertion_response, challenge_bytes, challenge_store)',
        "replacement": '        pass # MUTATION_111_BYPASS_MAIL_SEND_WEBAUTHN',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_mail_calendar.TestMailCalendarWorkflows.test_10_send_denied_with_wrong_challenge_or_forged_assertion"]
    },
    {
        "id": "MUTATION_112_BROWSER_TOCTOU_WEBAUTHN_BYPASS",
        "name": "Bypass Gated Submit TOCTOU Check in helm_browser_broker.py",
        "file": os.path.join(BASE_DIR, "helm_browser_broker.py"),
        "target": '        if current_snap.snapshot_hash != prior_snapshot.snapshot_hash:',
        "replacement": '        if False: # MUTATION_112_BYPASS_TOCTOU',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_browser_broker.TestBrowserBroker.test_7_browser_gated_submit_with_webauthn_and_toctou"]
    }
]


def _safe_write(path: str, content: str, retries: int = 5):
    for i in range(retries):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(0.15)


def _safe_copy(src: str, dst: str, retries: int = 5):
    for i in range(retries):
        try:
            shutil.copy2(src, dst)
            return
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(0.15)


def run_mutation_tests() -> bool:
    print("=" * 75)
    print("=== BATCH 39 EXPANDED AUTOMATED CI MUTATION TEST HARNESS (75 DEFENSES) ===")
    print("=" * 75)
    print(f"Total Security Mutations to Evaluate: {len(MUTATIONS)}\n")

    all_killed = True
    results = []

    for idx, mut in enumerate(MUTATIONS, 1):
        mid = mut["id"]
        name = mut["name"]
        file_path = mut["file"]
        target = mut["target"]
        replacement = mut["replacement"]
        test_cmd = mut["test_cmd"]

        print(f"[{idx}/{len(MUTATIONS)}] Testing Mutation: {name}")
        print(f"    File: {os.path.basename(file_path)}")

        if not os.path.exists(file_path):
            print(f"    ❌ ERROR: Target file '{file_path}' does not exist!")
            all_killed = False
            results.append((mid, "FILE_NOT_FOUND"))
            continue

        with open(file_path, "r", encoding="utf-8") as f:
            original_content = f.read()

        if target not in original_content:
            print(f"    ❌ ERROR: Target string for mutation not found in '{os.path.basename(file_path)}'!")
            all_killed = False
            results.append((mid, "TARGET_NOT_FOUND"))
            continue

        backup_path = file_path + ".mut_bak"
        _safe_copy(file_path, backup_path)

        try:
            mutated_content = original_content.replace(target, replacement, 1)

            # Rigor Check: Ensure mutated content is syntactically valid before testing
            import ast
            try:
                ast.parse(mutated_content)
            except SyntaxError as syn_err:
                print(f"    ❌ MUTATION_SYNTAX_ERROR: Mutated code failed ast.parse: {syn_err}")
                all_killed = False
                results.append((mid, "MUTATION_SYNTAX_ERROR", str(syn_err)))
                continue

            _safe_write(file_path, mutated_content)

            proc = subprocess.run(
                test_cmd,
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )

            # If the test passes (exit code 0), the mutation SURVIVED -> FAILURE
            if proc.returncode == 0:
                print(f"    🚨 MUTATION SURVIVED! Security control is not actively defending.")
                print(f"       Exit code: {proc.returncode}")
                all_killed = False
                results.append((mid, "SURVIVED", None))
            else:
                killer = None
                combined_out = (proc.stdout or "") + "\n" + (proc.stderr or "")
                for line in combined_out.splitlines():
                    if "FAILED " in line:
                        killer = line.replace("FAILED ", "").strip().split(" ")[0]
                        break
                    elif line.startswith("FAIL: ") or "FAIL: test_" in line:
                        killer = line.replace("FAIL: ", "").strip().split(" ")[0]
                        break
                    elif line.startswith("ERROR: ") or "ERROR: test_" in line:
                        killer = line.replace("ERROR: ", "").strip().split(" ")[0]
                        break
                    elif "AssertionError" in line or "Error:" in line:
                        if not killer:
                            killer = line.strip()[:80]
                if not killer:
                    killer = test_cmd[-1] if test_cmd else "unknown_test"
                print(f"    ✅ MUTATION KILLED! Test failed as expected (exit code {proc.returncode}).")
                print(f"       Killed by: {killer}")
                results.append((mid, "KILLED", killer))

        except subprocess.TimeoutExpired:
            print(f"    ✅ MUTATION KILLED! Test timed out / hung due to mutation.")
            results.append((mid, "KILLED", "TimeoutExpired"))
        except Exception as e:
            print(f"    ⚠️ Exception during mutation testing: {e}")
            results.append((mid, f"ERROR: {e}", str(e)))
            all_killed = False
        finally:
            if os.path.exists(backup_path):
                try:
                    _safe_copy(backup_path, file_path)
                except Exception:
                    pass
                for _ in range(5):
                    try:
                        os.remove(backup_path)
                        break
                    except Exception:
                        time.sleep(0.1)

    print("\n" + "=" * 75)
    print("=== MUTATION TEST SUMMARY REPORT ===")
    print("=" * 75)
    killed_count = 0
    for item in results:
        mid, status = item[0], item[1]
        killer = item[2] if len(item) > 2 and item[2] else ""
        icon = "✅" if status == "KILLED" else "❌"
        killer_str = f" [by: {killer.split('::')[-1]}]" if killer else ""
        print(f"  {icon} {mid:<45}: {status}{killer_str}")
        if status == "KILLED":
            killed_count += 1

    print("-" * 75)
    rate = (killed_count / len(MUTATIONS)) * 100.0 if MUTATIONS else 0.0
    print(f"MUTATION KILL RATE: {killed_count}/{len(MUTATIONS)} ({rate:.1f}%)")
    print("=" * 75 + "\n")

    if all_killed:
        print("✅ 100% MUTATION KILL RATE ACHIEVED. All security controls mathematically verified.\n")
        return True
    else:
        print("❌ CRITICAL: One or more mutations survived! Security defense bypass detected.\n")
        return False


if __name__ == "__main__":
    success = run_mutation_tests()
    sys.exit(0 if success else 1)
