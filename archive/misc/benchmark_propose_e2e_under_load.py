"""benchmark_propose_e2e_under_load.py - End-to-End Proposal Benchmark Under Real CPU Load.

Measures full two-phase propose-to-outcome transactions across the Named Pipe:
- Evaluates complete mediation: Canary scan, envelope check, HMAC intent token minting,
  synchronous SQLite ledger INTENT commit, actuator execution, and synchronous SQLite OUTCOME commit.
- Executes under artificial CPU load (multithreaded arithmetic burn).
- Computes Min, Mean, Median, P90, P95, P99, P99.9, and Max round-trip latency.
- Records all raw latency measurements to propose_e2e_benchmark_samples.json.
"""

import os
import sys
import time
import json
import math
import threading
import statistics

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor

def cpu_burner(stop_event):
    """Spins on floating-point arithmetic to generate sustained CPU contention."""
    x = 1.0
    while not stop_event.is_set():
        x = math.sin(x) + math.cos(x) * 1.0001
        if x > 1e6:
            x = 1.0

def run_e2e_benchmark(num_samples: int = 100):
    client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=r"\\.\pipe\homie_supervisor")
    if not client.connect(timeout_sec=2.0):
        print("ERROR: Could not connect to supervisor named pipe!")
        return None

    # Start 2 CPU burner threads to saturate host cores
    stop_event = threading.Event()
    burners = [threading.Thread(target=cpu_burner, args=(stop_event,), daemon=True) for _ in range(2)]
    for b in burners:
        b.start()

    print(f"Running {num_samples} full two-phase WRITE_EXEC proposals under CPU load...")

    # Warmup
    for _ in range(5):
        client.propose("homie_snap_window", {"app_name": "notepad"}, caller_id="benchmark_client")

    samples = []
    for i in range(num_samples):
        req_id = f"bench_req_{int(time.time()*1000)}_{i}"
        t0 = time.perf_counter()
        resp = client.propose(
            "homie_snap_window",
            {"app_name": "notepad"},
            caller_id="benchmark_client"
        )
        t1 = time.perf_counter()
        duration_ms = (t1 - t0) * 1000.0
        samples.append({
            "iteration": i + 1,
            "req_id": req_id,
            "latency_ms": round(duration_ms, 3),
            "status": resp.get("status"),
            "has_intent_token": bool(resp.get("intent_token"))
        })

    # Stop burner threads
    stop_event.set()
    for b in burners:
        b.join(timeout=0.5)

    client.close()

    latencies = [s["latency_ms"] for s in samples]
    latencies_sorted = sorted(latencies)

    n = len(latencies_sorted)
    min_lat = latencies_sorted[0]
    max_lat = latencies_sorted[-1]
    mean_lat = statistics.mean(latencies)
    median_lat = statistics.median(latencies)
    p90_lat = latencies_sorted[int(n * 0.90)]
    p95_lat = latencies_sorted[int(n * 0.95)]
    p99_lat = latencies_sorted[int(n * 0.99)]
    p999_lat = latencies_sorted[min(n - 1, int(n * 0.999))]

    stats = {
        "num_samples": num_samples,
        "min_ms": min_lat,
        "mean_ms": round(mean_lat, 3),
        "median_ms": round(median_lat, 3),
        "p90_ms": round(p90_lat, 3),
        "p95_ms": round(p95_lat, 3),
        "p99_ms": round(p99_lat, 3),
        "p99_9_ms": round(p999_lat, 3),
        "max_ms": max_lat,
        "all_succeeded": all(s["status"] in ("ALLOW", "OUTCOME") or s.get("has_intent_token") for s in samples)
    }

    print("\n=== E2E PROPOSE-TO-OUTCOME BENCHMARK (UNDER CPU LOAD) ===")
    print(f"  Samples:    {num_samples}")
    print(f"  Min:        {min_lat:.3f} ms")
    print(f"  Mean:       {mean_lat:.3f} ms")
    print(f"  Median:     {median_lat:.3f} ms")
    print(f"  P90:        {p90_lat:.3f} ms")
    print(f"  P95:        {p95_lat:.3f} ms")
    print(f"  P99:        {p99_lat:.3f} ms")
    print(f"  P99.9:      {p999_lat:.3f} ms")
    print(f"  Max:        {max_lat:.3f} ms")
    print("=========================================================")

    output_data = {
        "timestamp": time.time(),
        "stats": stats,
        "samples": samples
    }
    with open("propose_e2e_benchmark_samples.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print("Saved propose_e2e_benchmark_samples.json")
    return stats

if __name__ == "__main__":
    run_e2e_benchmark(100)
