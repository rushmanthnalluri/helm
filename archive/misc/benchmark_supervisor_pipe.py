"""benchmark_supervisor_pipe.py - High-Resolution Benchmark of Homie Supervisor Named Pipe.

Measures round-trip latency through the Windows Named Pipe server under load:
- Computes Min, Mean, Median, P90, P95, P99, and Max latency (in milliseconds).
- Records raw sample timestamps and round-trip timings into pipe_benchmark_samples.json.
"""

import os
import sys
import time
import json
import statistics

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor

def run_benchmark(num_samples: int = 500):
    client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=r"\\.\pipe\homie_supervisor")
    if not client.connect(timeout_sec=2.0):
        print("ERROR: Could not connect to supervisor named pipe!")
        return None

    samples = []
    print(f"Running {num_samples} round-trip requests through named pipe under load...")

    # Warmup
    for _ in range(10):
        client.heartbeat(progress_counter=1)

    for i in range(num_samples):
        t0 = time.perf_counter()
        resp = client.heartbeat(progress_counter=i + 2)
        t1 = time.perf_counter()
        duration_ms = (t1 - t0) * 1000.0
        samples.append({
            "iteration": i + 1,
            "latency_ms": round(duration_ms, 3),
            "status": resp.get("status")
        })

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

    stats = {
        "num_samples": num_samples,
        "min_ms": min_lat,
        "mean_ms": round(mean_lat, 3),
        "median_ms": round(median_lat, 3),
        "p90_ms": round(p90_lat, 3),
        "p95_ms": round(p95_lat, 3),
        "p99_ms": round(p99_lat, 3),
        "max_ms": max_lat
    }

    print("\n=== NAMED PIPE IPC LATENCY BENCHMARK ===")
    print(f"  Samples: {num_samples}")
    print(f"  Min:     {min_lat:.3f} ms")
    print(f"  Mean:    {mean_lat:.3f} ms")
    print(f"  Median:  {median_lat:.3f} ms")
    print(f"  P90:     {p90_lat:.3f} ms")
    print(f"  P95:     {p95_lat:.3f} ms")
    print(f"  P99:     {p99_lat:.3f} ms")
    print(f"  Max:     {max_lat:.3f} ms")
    print("========================================")

    output_data = {
        "timestamp": time.time(),
        "stats": stats,
        "samples": samples
    }
    with open("pipe_benchmark_samples.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print("Saved pipe_benchmark_samples.json")
    return stats

if __name__ == "__main__":
    run_benchmark(500)
