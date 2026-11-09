"""scripts/append_round53_mutations.py - Safely appends mutations 107-110 to scripts/run_mutation_tests.py.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUT_FILE = os.path.join(BASE_DIR, "scripts", "run_mutation_tests.py")

with open(MUT_FILE, "r", encoding="utf-8") as f:
    text = f.read()

target = '''        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_plan_envelopes.py::TestPlanEnvelopes::test_4_unexpected_taint_invalidates_plan"]
    }
]'''

addition = '''        "test_cmd": [sys.executable, "-m", "pytest", "tests/test_plan_envelopes.py::TestPlanEnvelopes::test_4_unexpected_taint_invalidates_plan"]
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
    }
]'''

if target in text:
    new_text = text.replace(target, addition, 1)
    with open(MUT_FILE, "w", encoding="utf-8") as f:
        f.write(new_text)
    print("Successfully appended mutations 107-110!")
elif "MUTATION_107" in text:
    print("Mutations 107-110 already present.")
else:
    print("ERROR: Target anchor not found in run_mutation_tests.py!")
    sys.exit(1)
