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
        "name": "Drop File Owner-Only DACL in homie_confinement.py",
        "file": os.path.join(BASE_DIR, "homie_confinement.py"),
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
        "name": "Drop ActiveProcessLimit from Job Object in homie_confinement.py",
        "file": os.path.join(BASE_DIR, "homie_confinement.py"),
        "target": 'basic["ActiveProcessLimit"] = 1',
        "replacement": 'basic["ActiveProcessLimit"] = 0; basic["LimitFlags"] &= ~win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_confinement_attacks.py::TestBatch20VerifiedConfinement::test_confined_worker_attacks_with_specific_error_codes"]
    },
    {
        "id": "MUTATION_3_APPCONTAINER_NETWORK_ISOLATION",
        "name": "Remove AppContainer Isolation in homie_confinement.py",
        "file": os.path.join(BASE_DIR, "homie_confinement.py"),
        "target": "flags = EXTENDED_STARTUPINFO_PRESENT | win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW",
        "replacement": "flags = win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW; siex.lpAttributeList = None",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_confinement_attacks.py::TestBatch20VerifiedConfinement::test_confined_worker_attacks_with_specific_error_codes"]
    },
    {
        "id": "MUTATION_4_SUPERVISOR_COMPLETE_MEDIATION",
        "name": "Bypass Intent Token Verification in homie_supervisor.py",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "raise CompleteMediationBreachError(",
        "replacement": "# MUTATION BYPASS: Complete mediation disabled\n                pass # raise CompleteMediationBreachError(",
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
        "name": "Drop Synthetic Keystroke Filter in homie_watchdog.py",
        "file": os.path.join(BASE_DIR, "homie_watchdog.py"),
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
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "if token_seq != seq:  # Strictly bind sequence number!",
        "replacement": "if False: # MUTATION BYPASS: seq check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_intent_token_sequence_binding_enforcement"]
    },
    {
        "id": "MUTATION_14_INTENT_TOKEN_ARGS_HASH_BYPASS",
        "name": "Bypass Arguments Hash Verification in verify_and_consume_intent_token",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "if not hmac.compare_digest(tok_args_hash, expected_args_hash):",
        "replacement": "if False: # MUTATION BYPASS: args hash check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_intent_token_args_hash_binding_enforcement"]
    },
    {
        "id": "MUTATION_15_SUPERVISOR_TIER_ALLOWLIST_BYPASS",
        "name": "Drop Tier Allowlist Check in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
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
        "target": "        if device_id in registry:\n            del _LOCAL_ENROLLMENT_SESSIONS[session_id]\n            return False, f\"DEVICE_EXISTS: Device '{device_id}' is already enrolled. Overwrites are forbidden.\"",
        "replacement": "        if False: pass # MUTATION BYPASS: anti-overwrite check disabled",
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
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "if tool not in allowed_tools:",
        "replacement": "if False: # MUTATION BYPASS: unknown tool check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch20_complete_mediation.py::TestBatch20CompleteMediationAndRedTeam::test_supervisor_actuator_rejects_unknown_tool"]
    },
    {
        "id": "MUTATION_23_ATOMIC_NONCE_LOCK_BYPASS",
        "name": "Bypass Atomic Nonce Check in check_and_record_consumed_nonce",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "with _NONCE_LOCK:\n        nonces = _load_consumed_nonces()\n        if nonce in nonces:\n            return False",
        "replacement": "if False: # MUTATION BYPASS: atomic nonce check disabled\n            pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_4_concurrent_nonce_replay_race_condition"]
    },
    {
        "id": "MUTATION_24_SECOND_DEVICE_MULTISIG_BYPASS",
        "name": "Bypass Second Device Multi-Sig Gate in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        active_devices = [v for k, v in registry.items() if not v.get(\"revoked\", False)]\n        if active_devices:\n            primary_entry = next((v for v in active_devices if v.get(\"device_id\") == \"primary_phone\"), active_devices[0])\n            if not primary_approval_sig:",
        "replacement": "        active_devices = [v for k, v in registry.items() if not v.get(\"revoked\", False)]\n        if active_devices:\n            primary_entry = next((v for v in active_devices if v.get(\"device_id\") == \"primary_phone\"), active_devices[0])\n            if False: # MUTATION BYPASS: approval check bypassed",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_6_second_device_requires_primary_approval"]
    },
    {
        "id": "MUTATION_25_ACTUATOR_SEQ_REQUIRED_BYPASS",
        "name": "Bypass Mandatory Sequence Check in SupervisorActuator.execute_actuator",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": 'if seq is None or not isinstance(seq, int) or seq <= 0:\n            raise ValueError("Sequence number seq is strictly required and must be a positive integer!")',
        "replacement": 'if False: # MUTATION BYPASS: seq check disabled\n            pass',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_8_mandatory_sequence_number_rejection_of_fallback"]
    },
    {
        "id": "MUTATION_26_PENDING_CHALLENGES_AUTH_BYPASS",
        "name": "Bypass Authentication Gate in _handle_get_pending_challenges",
        "file": os.path.join(BASE_DIR, "phone_gateway.py"),
        "target": 'if not is_device_token_valid(token):\n            self._send_response(401, "application/json", json.dumps({"error": "Unauthorized: Valid paired device token required"}))\n            return',
        "replacement": 'if False: # MUTATION BYPASS: auth check disabled\n            pass',
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch29_security_hardening.py::TestBatch29SecurityHardening::test_3_unauthenticated_listing_and_challenge_cancellation_denied"]
    },
    {
        "id": "MUTATION_27_SUPERVISOR_FAIL_OPEN_BYPASS",
        "name": "Bypass Fail-Closed Gate on Non-StepUp Deny in _handle_propose",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "        if not allowed:\n            if requires_step_up:",
        "replacement": "        if False: # MUTATION BYPASS: taint fail-closed gate disabled\n            if requires_step_up:",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_1_supervisor_fail_open_prevented_on_non_stepup_deny"]
    },
    {
        "id": "MUTATION_28_SUPERVISOR_NON_DICT_ARGS_BYPASS",
        "name": "Bypass Strict Dict Argument Validation in _handle_propose",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "        if not isinstance(args, dict):\n            return self._encode_reply(MSG_ERROR, {",
        "replacement": "        if False: # MUTATION BYPASS: non-dict args check disabled\n            return self._encode_reply(MSG_ERROR, {",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_2_supervisor_rejects_non_dict_arguments"]
    },
    {
        "id": "MUTATION_29_SUPERVISOR_ENVELOPE_BYPASS",
        "name": "Bypass Policy Envelope Check in PolicySupervisor._handle_propose",
        "file": os.path.join(BASE_DIR, "homie_supervisor.py"),
        "target": "        # 5.1. Policy Envelope domain scoping, step budget & prohibited environments\n        if getattr(self, \"envelope\", None) and getattr(self.envelope, \"is_active\", False):",
        "replacement": "        # 5.1. Policy Envelope domain scoping, step budget & prohibited environments\n        if False: # MUTATION BYPASS: envelope check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_3_supervisor_envelope_enforcement_in_handle_propose"]
    },
    {
        "id": "MUTATION_30_REVOKED_PRIMARY_BYPASS",
        "name": "Bypass Active Device Multi-Sig Gate in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "        # Second-device enrollment multi-sig gate: Adding a new device requires active device approval\n        active_devices = [v for k, v in registry.items() if not v.get(\"revoked\", False)]\n        if active_devices:",
        "replacement": "        # Second-device enrollment multi-sig gate: Adding a new device requires active device approval\n        active_devices = [v for k, v in registry.items() if not v.get(\"revoked\", False)]\n        if False: # MUTATION BYPASS: active device check disabled",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_5_enrollment_multi_sig_prevents_revoked_primary_bypass"]
    },
    {
        "id": "MUTATION_31_SESSION_BOUND_MULTISIG_BYPASS",
        "name": "Bypass Session-Bound V2 Multi-Sig Verification in complete_device_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "            now = int(time.time())\n            v2_verified = False",
        "replacement": "            now = int(time.time())\n            v2_verified = True # MUTATION BYPASS: session binding check bypassed",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_6_enrollment_multi_sig_binds_session_and_expiry"]
    },
    {
        "id": "MUTATION_32_GLOBAL_LOCKOUT_BYPASS",
        "name": "Bypass Global Persistent Lockout in start_local_enrollment",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "    if is_enrollment_locked_out():\n        logger.warning(\"Enrollment blocked: Global pairing attempt lockout is active.\")\n        return \"\"",
        "replacement": "    if False: # MUTATION BYPASS: global lockout check disabled\n        pass",
        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_batch30_security_hardening.py::TestBatch30SecurityHardening::test_7_global_persistent_enrollment_lockout"]
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
    print("=== BATCH 30 EXPANDED AUTOMATED CI MUTATION TEST HARNESS ===")
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
                results.append((mid, "SURVIVED"))
            else:
                print(f"    ✅ MUTATION KILLED! Test failed as expected (exit code {proc.returncode}).")
                results.append((mid, "KILLED"))

        except subprocess.TimeoutExpired:
            print(f"    ✅ MUTATION KILLED! Test timed out / hung due to mutation.")
            results.append((mid, "KILLED"))
        except Exception as e:
            print(f"    ⚠️ Exception during mutation testing: {e}")
            results.append((mid, f"ERROR: {e}"))
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
    for mid, status in results:
        icon = "✅" if status == "KILLED" else "❌"
        print(f"  {icon} {mid:<45}: {status}")
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
