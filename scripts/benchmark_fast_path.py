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

import homie_supervisor
import homie_mcp

def benchmark(n_iterations=50):
    os.environ["HOMIE_TEST_ENV"] = "1"
    os.environ["HOMIE_COMPLETE_MEDIATION"] = "1"

    supervisor = homie_supervisor.PolicySupervisor()
    supervisor.state = homie_supervisor.STATE_ARMED
    actuator = supervisor.actuator

    latencies_ms = []

    for seq in range(1, n_iterations + 1):
        caller_id = f"worker_{seq}" # Avoid rate limiting
        args = {"app_name": "notepad"}
        tool = "homie_snap_window"
        req_id = f"bench_{seq}"

        t0 = time.perf_counter()

        # Step 1: Supervisor mints INTENT_V2 token
        token = supervisor.mint_intent_token(tool, args, caller_id, seq)

        # Step 2: Actuator verifies and consumes INTENT_V2 token & dispatches tool
        res = actuator.execute_actuator(
            tool, args, caller_id=caller_id, intent_token=token
        )

        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    supervisor.clean_shutdown()

    p50 = statistics.median(latencies_ms)
    p95 = statistics.quantiles(latencies_ms, n=20)[18]  # 95th percentile
    p99 = statistics.quantiles(latencies_ms, n=100)[98] # 99th percentile
    min_lat = min(latencies_ms)
    max_lat = max(latencies_ms)

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
