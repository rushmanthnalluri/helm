#!/usr/bin/env python3
"""startup_bench.py - Benchmark cold-start import latencies for heavy modules.

Measures the isolated import time of each heavy C-extension and Python library
used by Helm, printing a sorted table ranked by latency.
Also measures app startup import time (before vs after lazy loading).
"""

import importlib
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

HEAVY_MODULES = [
    "torch",
    "sentence_transformers",
    "faster_whisper",
    "ctranslate2",
    "winrt",
    "cryptography",
    "openpyxl",
    "webview",
    "pyautogui",
    "pyperclip",
    "PIL",
]


def measure_module_import_isolated(module_name: str, timeout: float = 120.0) -> Tuple[Optional[float], Optional[str]]:
    """Measures the import time of a module in an isolated fresh Python process."""
    code = (
        "import time, importlib\n"
        "t0 = time.perf_counter()\n"
        f"importlib.import_module({module_name!r})\n"
        "t1 = time.perf_counter()\n"
        "print(f'{t1 - t0:.6f}')\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        if proc.returncode == 0:
            val = float(proc.stdout.strip())
            return val, None
        else:
            err = proc.stderr.strip() or f"exit code {proc.returncode}"
            return None, err
    except subprocess.TimeoutExpired:
        return None, "Timed out (>30s)"
    except Exception as e:
        return None, str(e)


def measure_app_import_time() -> Optional[float]:
    """Measures the import time of app.py in an isolated process."""
    code = (
        "import time\n"
        "t0 = time.perf_counter()\n"
        "import app\n"
        "t1 = time.perf_counter()\n"
        "print(f'{t1 - t0:.6f}')\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False
        )
        if proc.returncode == 0:
            return float(proc.stdout.strip())
    except Exception:
        pass
    return None


def run_benchmark() -> List[Tuple[str, Optional[float], Optional[str]]]:
    print("=" * 65)
    print(" HELM COLD-START IMPORT BENCHMARK (ISOLATED PROCESS TIMING)")
    print("=" * 65)
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    print(f"Platform: {sys.platform}")
    print("-" * 65)

    results: List[Tuple[str, Optional[float], Optional[str]]] = []
    for mod in HEAVY_MODULES:
        print(f"  Measuring {mod:<25} ... ", end="", flush=True)
        t, err = measure_module_import_isolated(mod)
        if t is not None:
            print(f"{t:.4f}s")
        else:
            print(f"ERROR ({err})")
        results.append((mod, t, err))

    # Sort descending by import time (None/errors at bottom)
    results.sort(key=lambda r: (r[1] is not None, r[1] or 0.0), reverse=True)

    print("\n" + "=" * 65)
    print(f"| {'Module':<25} | {'Import Time (s)':<18} | {'Status':<12} |")
    print("|" + "-" * 27 + "|" + "-" * 20 + "|" + "-" * 14 + "|")
    total_time = 0.0
    for mod, t, err in results:
        if t is not None:
            total_time += t
            status = "OK"
            time_str = f"{t:>15.4f}s"
        else:
            status = "FAILED"
            time_str = f"{'N/A':>16}"
        print(f"| {mod:<25} | {time_str} | {status:<12} |")
    print("=" * 65)
    print(f"Cumulative serial import cost: {total_time:.4f}s")

    app_time = measure_app_import_time()
    if app_time is not None:
        print(f"app.py cold-start import time: {app_time:.4f}s")
    print("=" * 65)
    return results


if __name__ == "__main__":
    run_benchmark()
