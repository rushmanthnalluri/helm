"""scripts/test_mutations_107_110.py - Quickly tests mutations 107 to 110.
"""

import os
import sys
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scripts.run_mutation_tests import MUTATIONS, _safe_copy, _safe_write

new_muts = [m for m in MUTATIONS if m["id"] in (
    "MUTATION_107_WEBAUTHN_UV_BYPASS",
    "MUTATION_108_WEBAUTHN_SYNCED_PASSKEY_BE_BYPASS",
    "MUTATION_109_WEBAUTHN_SIGN_COUNT_ROLLBACK_BYPASS",
    "MUTATION_110_INJECTION_BASELINE_ZERO_POLICY_ASR_BYPASS"
)]

print(f"Testing {len(new_muts)} new security mutations...")
all_killed = True
for m in new_muts:
    mid = m["id"]
    name = m["name"]
    file_path = m["file"]
    target = m["target"]
    replacement = m["replacement"]
    test_cmd = m["test_cmd"]

    print(f"\n[*] Testing {mid}: {name}")
    with open(file_path, "r", encoding="utf-8") as f:
        orig = f.read()

    assert target in orig, f"Target not in {file_path}"
    backup = file_path + ".test_bak"
    _safe_copy(file_path, backup)

    try:
        mutated = orig.replace(target, replacement, 1)
        _safe_write(file_path, mutated)

        proc = subprocess.run(test_cmd, cwd=BASE_DIR, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            print(f"    🚨 SURVIVED! Exit code 0.")
            all_killed = False
        else:
            print(f"    ✅ KILLED! Exit code {proc.returncode}")
    finally:
        _safe_write(file_path, orig)
        if os.path.exists(backup):
            os.remove(backup)

if all_killed:
    print("\n✅ ALL 4 NEW SECURITY MUTATIONS (107-110) KILLED!")
else:
    print("\n❌ SOME MUTATIONS SURVIVED!")
    sys.exit(1)
