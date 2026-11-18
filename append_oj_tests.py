new_tests = """
    def test_13_hardware_profiler_system_specs_and_gpu_detection(self):
        \"\"\"OpenJarvis Directive: HardwareProfiler accurately profiles RAM, CPU cores, and GPU VRAM.\"\"\"
        import homie_hardware_profiler
        profiler = homie_hardware_profiler.HardwareProfiler()
        specs = profiler.get_system_specs()
        self.assertGreater(specs["total_ram_gb"], 0)
        self.assertGreater(specs["cpu_cores_logical"], 0)
        self.assertIsInstance(specs["gpus"], list)
        self.assertGreaterEqual(specs["total_vram_mb"], 0)

    def test_14_hardware_profiler_runtime_recommendation(self):
        \"\"\"OpenJarvis Directive: Recommends local runtime when sufficient GPU VRAM & Ollama available, cloud otherwise.\"\"\"
        import homie_hardware_profiler
        profiler = homie_hardware_profiler.HardwareProfiler()

        # Case A: Ample VRAM (8GB) and Ollama running with llama3
        mock_specs = {
            "total_ram_gb": 32.0, "available_ram_gb": 16.0,
            "cpu_cores_logical": 16, "cpu_cores_physical": 8,
            "gpus": [{"name": "NVIDIA GeForce RTX 4080", "vram_mb": 8192}],
            "total_vram_mb": 8192
        }
        mock_engines = {"ollama": {"available": True, "models": ["llama3:8b"]}, "llama_cpp": {"available": False, "models": []}}

        with patch.object(profiler, "get_system_specs", return_value=mock_specs), \\
             patch.object(profiler, "probe_local_engines", return_value=mock_engines):
            rec = profiler.recommend_runtime()
            self.assertEqual(rec["preferred_tier"], "LOCAL")
            self.assertEqual(rec["recommended_engine"], "ollama")
            self.assertEqual(rec["model_candidate"], "llama3:8b")

        # Case B: No local engine running -> defaults to CLOUD (Gemini Flash)
        mock_engines_none = {"ollama": {"available": False, "models": []}, "llama_cpp": {"available": False, "models": []}}
        with patch.object(profiler, "get_system_specs", return_value=mock_specs), \\
             patch.object(profiler, "probe_local_engines", return_value=mock_engines_none):
            rec_cloud = profiler.recommend_runtime()
            self.assertEqual(rec_cloud["preferred_tier"], "CLOUD")
            self.assertEqual(rec_cloud["model_candidate"], "gemini-2.5-flash")

    def test_15_resource_tracker_cost_and_flops_evaluation(self):
        \"\"\"OpenJarvis Directive: ResourceTracker calculates FLOPs (6*N*P) and token dollar costs.\"\"\"
        import homie_resource_tracker
        tracker = homie_resource_tracker.ResourceTracker(daily_budget_usd=10.0)

        # 1000 prompt tokens, 500 completion tokens on gemini-2.5-flash
        t = tracker.record_turn(
            model_name="gemini-2.5-flash",
            prompt_tokens=1000,
            completion_tokens=500,
            latency_ms=350.5,
            caller_id="assistant"
        )
        self.assertEqual(t["total_tokens"], 1500)
        self.assertGreater(t["estimated_cost_usd"], 0)
        self.assertGreater(t["estimated_flops"], 0)
        self.assertFalse(t["budget_exceeded"])
        self.assertEqual(tracker.daily_spend, t["estimated_cost_usd"])

    def test_16_resource_tracker_budget_circuit_breaker(self):
        \"\"\"OpenJarvis Directive: Circuit breaker triggers when daily expenditure exceeds configured limit.\"\"\"
        import homie_resource_tracker
        tracker = homie_resource_tracker.ResourceTracker(daily_budget_usd=0.001)

        # Large turn on claude-3-5-sonnet exceeding $0.001 limit
        t = tracker.record_turn(
            model_name="claude-3-5-sonnet",
            prompt_tokens=10000,
            completion_tokens=5000,
            latency_ms=1200.0,
            caller_id="assistant"
        )
        self.assertTrue(t["budget_exceeded"])
        self.assertGreater(tracker.daily_spend, 0.001)
"""

with open("tests/test_openjarvis_integration.py", "r", encoding="utf-8") as f:
    content = f.read()

target = "if __name__ == \"__main__\":"
assert target in content, "target not found"
content = content.replace(target, new_tests + "\n" + target)

with open("tests/test_openjarvis_integration.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Added tests 13-16 to tests/test_openjarvis_integration.py [OK]")
