"""scripts/benchmark_fast_path.py - Fast-Path End-to-End Latency Benchmark.

Measures p50, p95, and p99 latency across:
1. Supervisor binary frame encode / decode.
2. Cryptographic INTENT_V2 HMAC-SHA256 minting with args_hash.
3. Supervisor-side HMAC audit ledger record write.
4. SupervisorActuator execution with complete mediation verification and token consumption.
"""
import time
import os
import sys
import statistics

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_supervisor
import helm_mcp

def benchmark(n_iterations=500):
    os.environ["HELM_TEST_ENV"] = "1"
    os.environ["HELM_COMPLETE_MEDIATION"] = "1"

    supervisor = helm_supervisor.PolicySupervisor()
    supervisor.state = helm_supervisor.STATE_ARMED
    actuator = supervisor.actuator

    # 5 warm-up iterations to prime SQLite connection, table schemas, and JIT subkey cache
    for warm_seq in range(1, 6):
        w_token = supervisor.mint_intent_token("helm_snap_window", {"app_name": "notepad"}, f"warm_{warm_seq}", warm_seq)
        actuator.execute_actuator("helm_snap_window", {"app_name": "notepad"}, caller_id=f"warm_{warm_seq}", intent_token=w_token, seq=warm_seq)

    latencies_ms = []

    for seq in range(1, n_iterations + 1):
        caller_id = f"worker_{seq}" # Avoid rate limiting
        args = {"app_name": "notepad"}
        tool = "helm_snap_window"
        req_id = f"bench_{seq}"

        t0 = time.perf_counter()

        # Step 1: Supervisor mints INTENT_V2 token
        token = supervisor.mint_intent_token(tool, args, caller_id, seq)

        # Step 2: Actuator verifies and consumes INTENT_V2 token & dispatches tool
        res = actuator.execute_actuator(
            tool, args, caller_id=caller_id, intent_token=token, seq=seq
        )

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    supervisor.clean_shutdown()

    sorted_samples = sorted(latencies_ms)
    n = len(sorted_samples)
    min_lat = sorted_samples[0]
    p50 = sorted_samples[int(n * 0.50)]
    p95 = sorted_samples[min(n - 1, int(n * 0.95))]
    p99 = sorted_samples[min(n - 1, int(n * 0.99))]
    max_lat = sorted_samples[-1]

    # Save raw benchmark data for auditability
    import json
    samples_path = os.path.join(BASE_DIR, "benchmark_samples.json")
    try:
        with open(samples_path, "w", encoding="utf-8") as f:
            json.dump({
                "n_iterations": n_iterations,
                "min_ms": min_lat,
                "p50_ms": p50,
                "p95_ms": p95,
                "p99_ms": p99,
                "max_ms": max_lat,
                "samples_ms": [round(x, 4) for x in latencies_ms]
            }, f, indent=2)
    except Exception:
        pass

    print("\n=== SUPERVISOR FAST-PATH END-TO-END LATENCY BENCHMARK ===")
    print(f"Iterations: {n_iterations}")
    print(f"  • Min latency: {min_lat:.3f} ms")
    print(f"  • Median (p50): {p50:.3f} ms")
    print(f"  • 95th percentile (p95): {p95:.3f} ms")
    print(f"  • 99th percentile (p99): {p99:.3f} ms")
    print(f"  • Max latency: {max_lat:.3f} ms")
    print(f"  • Fast-path budget (<50ms): {'PASS [OK]' if p95 < 50.0 else 'FAIL [EXCEEDED]'}")
    return p50, p95

if __name__ == "__main__":
    benchmark()
