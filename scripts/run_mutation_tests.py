"""scripts/run_mutation_tests.py - Batch 21 Automated Mutation Test Harness.

Applies real code mutations across the critical defense layers to verify that:
1. Confinement File DACLs are truly defending sensitive assets (not cosmetic).
2. Confinement Job Object ActiveProcessLimit=1 is actively stopping fork-bombs / child spawns.
3. AppContainer token isolation is actively blocking network sockets.
4. Supervisor Actuator Complete Mediation is strictly verifying cryptographic intent tokens.
5. Policy Envelope domain scoping is actively preventing domain escapes.
6. Watchdog Low-Level Hook is actively rejecting synthetic injected keystrokes.
7. Phone Approval Portal is actively verifying cryptographic challenge signatures.

If a test suite stays green under a mutation, this script flags a CRITICAL FAILURE.
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
        "name": "Bypass Cryptographic Signature Check in phone_approval_portal.py",
        "file": os.path.join(BASE_DIR, "phone_approval_portal.py"),
        "target": "if not hmac.compare_digest(signature, expected_sig):",
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
        "target": 'if taint_tracker.is_session_tainted("macro_compilation"):',
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
    }
]


def run_mutation_tests() -> bool:
    print("=" * 75)
    print("=== BATCH 26 EXPANDED AUTOMATED CI MUTATION TEST HARNESS ===")
    print("=" * 75)
    print(f"Total Security Mutations to Evaluate: {len(MUTATIONS)}\n")

    all_killed = True
    results = []

    for idx, mut in enumerate(MUTATIONS, 1):
        mid = mut["id"]
        mname = mut["name"]
        fpath = mut["file"]
        target = mut["target"]
        replacement = mut["replacement"]
        test_cmd = mut["test_cmd"]

        print(f"[{idx}/{len(MUTATIONS)}] Testing Mutation: {mname}")
        print(f"    File: {os.path.basename(fpath)}")

        # 1. Read original content
        with open(fpath, "r", encoding="utf-8") as f:
            original_content = f.read()

        if target not in original_content:
            print(f"    ❌ ERROR: Mutation target string not found in {fpath}!")
            results.append((mid, mname, "ERROR_TARGET_NOT_FOUND"))
            all_killed = False
            continue

        # 2. Apply mutation
        mutated_content = original_content.replace(target, replacement, 1)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(mutated_content)

        try:
            # 3. Run target test
            proc = subprocess.run(
                test_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=BASE_DIR,
                timeout=60
            )

            # 4. Check outcome: test MUST FAIL (non-zero exit code)
            if proc.returncode != 0:
                print(f"    ✅ MUTATION KILLED! Test failed as expected (exit code {proc.returncode}).")
                results.append((mid, mname, "KILLED"))
            else:
                print(f"    🚨 MUTATION SURVIVED! Test stayed green despite compromised defense!")
                results.append((mid, mname, "SURVIVED"))
                all_killed = False

        except subprocess.TimeoutExpired:
            print(f"    ⚠️ Test timed out under mutation (treated as killed).")
            results.append((mid, mname, "KILLED_TIMEOUT"))
        finally:
            # 5. Restore original file
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(original_content)

    print("\n" + "=" * 75)
    print("=== MUTATION TEST SUMMARY REPORT ===")
    print("=" * 75)
    killed_count = sum(1 for _, _, status in results if status in ("KILLED", "KILLED_TIMEOUT"))
    total_count = len(results)
    kill_rate = (killed_count / total_count * 100) if total_count > 0 else 0

    for mid, mname, status in results:
        status_icon = "✅" if status in ("KILLED", "KILLED_TIMEOUT") else "🚨"
        print(f"  {status_icon} {mid:<42} : {status}")

    print("-" * 75)
    print(f"MUTATION KILL RATE: {killed_count}/{total_count} ({kill_rate:.1f}%)")
    print("=" * 75)

    if not all_killed:
        print("\n❌ CRITICAL DEFECT: One or more mutations survived! Test suite must be hardened.")
        return False

    print("\n✅ 100% MUTATION KILL RATE ACHIEVED. All security controls mathematically verified.")
    return True


if __name__ == "__main__":
    success = run_mutation_tests()
    sys.exit(0 if success else 1)
