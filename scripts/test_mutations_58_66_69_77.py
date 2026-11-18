import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

import run_mutation_tests

targets = [
    "MUTATION_58_RECOVERY_TOKEN_CROSS_PROCESS_SQLITE_BYPASS",
    "MUTATION_66_ANTI_BURN_DOS_SQLITE_LOOP_BYPASS",
    "MUTATION_69_PERSISTENT_NONCE_CONSUMPTION_BYPASS",
    "MUTATION_77_ZERO_TRUST_NO_DEVICE_BYPASS"
]

all_mutations = run_mutation_tests.MUTATIONS
selected = [m for m in all_mutations if m["id"] in targets]

print(f"Testing {len(selected)} selected mutations...")
run_mutation_tests.MUTATIONS = selected
success = run_mutation_tests.run_mutation_tests()
sys.exit(0 if success else 1)
