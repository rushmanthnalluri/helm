import sys
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import subprocess
from scripts.run_mutation_tests import MUTATIONS, _safe_copy, _safe_write

print(f"Total mutations: {len(MUTATIONS)}")
new_muts = MUTATIONS[98:]
print(f"Testing {len(new_muts)} new mutations (indices 99-{len(MUTATIONS)}):")
all_killed = True
for m in new_muts:
    mid = m["id"]
    name = m["name"]
    print(f"==> {mid}: {name}")
    file_path = m["file"]
    with open(file_path, "r", encoding="utf-8") as f:
        orig = f.read()
    if m["target"] not in orig:
        print(f"    ❌ TARGET NOT FOUND in {os.path.basename(file_path)}")
        all_killed = False
        continue
    bak = file_path + ".test_bak"
    _safe_copy(file_path, bak)
    try:
        mutated = orig.replace(m["target"], m["replacement"], 1)
        _safe_write(file_path, mutated)
        proc = subprocess.run(m["test_cmd"], cwd=BASE_DIR, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            print(f"    ✅ KILLED! Exit code {proc.returncode}")
        else:
            print(f"    🚨 SURVIVED! Exit code 0")
            all_killed = False
    finally:
        _safe_copy(bak, file_path)
        if os.path.exists(bak):
            os.remove(bak)

print(f"All new mutations killed: {all_killed}")
