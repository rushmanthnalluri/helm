"""helm_hardware_profiler.py - Local-First Hardware & Inference Engine Profiler.

Inspired by OpenJarvis (Stanford) local-first architecture:
- Probes system hardware (RAM, CPU cores, GPU VRAM).
- Detects local inference runtimes (Ollama, llama.cpp, vLLM).
- Recommends the optimal model tier and runtime (local vs cloud hybrid).
- Enables zero-network local fallback when offline.
"""

import os
import sys
import json
import logging
import urllib.request
import psutil
from typing import Dict, Any, List, Optional

logger = logging.getLogger("helm.hardware_profiler")


class HardwareProfiler:
    """Inspects machine compute capability and available local inference runtimes."""

    def __init__(self, ollama_url: str = "http://127.0.0.1:11434", llama_cpp_url: str = "http://127.0.0.1:8080"):
        self.ollama_url = ollama_url
        self.llama_cpp_url = llama_cpp_url

    def get_system_specs(self) -> Dict[str, Any]:
        """Returns hardware specifications of the host."""
        mem = psutil.virtual_memory()
        total_ram_gb = round(mem.total / (1024 ** 3), 1)
        avail_ram_gb = round(mem.available / (1024 ** 3), 1)
        cpu_cores = psutil.cpu_count(logical=True) or 1
        physical_cores = psutil.cpu_count(logical=False) or 1

        gpus = self._detect_gpus()
        total_vram_mb = sum(g.get("vram_mb", 0) for g in gpus)

        return {
            "total_ram_gb": total_ram_gb,
            "available_ram_gb": avail_ram_gb,
            "cpu_cores_logical": cpu_cores,
            "cpu_cores_physical": physical_cores,
            "gpus": gpus,
            "total_vram_mb": total_vram_mb
        }

    def _detect_gpus(self) -> List[Dict[str, Any]]:
        """Detects graphics adapters and dedicated VRAM on Windows."""
        gpus = []
        if sys.platform == "win32":
            try:
                import subprocess
                cmd = "Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM | ConvertTo-Json"
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", cmd],
                    capture_output=True, text=True, timeout=3
                )
                if res.returncode == 0 and res.stdout.strip():
                    raw = json.loads(res.stdout)
                    items = [raw] if isinstance(raw, dict) else raw
                    for item in items:
                        name = item.get("Name") or "Unknown GPU"
                        raw_ram = item.get("AdapterRAM") or 0
                        vram_mb = round(int(raw_ram) / (1024 ** 2))
                        gpus.append({"name": name, "vram_mb": vram_mb})
            except Exception as e:
                logger.debug("GPU detection error: %s", e)
        return gpus

    def probe_local_engines(self, timeout_sec: float = 0.3) -> Dict[str, Any]:
        """Checks if local inference servers are actively running."""
        engines = {
            "ollama": {"available": False, "models": []},
            "llama_cpp": {"available": False, "models": []}
        }

        # 1. Probe Ollama
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", headers={"User-Agent": "HelmAgent/1.0"})
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    models = [m.get("name") for m in data.get("models", [])]
                    engines["ollama"] = {"available": True, "models": models}
        except Exception:
            pass

        # 2. Probe llama.cpp server
        try:
            req = urllib.request.Request(f"{self.llama_cpp_url}/health", headers={"User-Agent": "HelmAgent/1.0"})
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status == 200:
                    engines["llama_cpp"] = {"available": True, "models": ["llama_cpp_server"]}
        except Exception:
            pass

        return engines

    def recommend_runtime(self) -> Dict[str, Any]:
        """Determines whether to run local, cloud, or hybrid models based on hardware and engine availability."""
        specs = self.get_system_specs()
        engines = self.probe_local_engines()

        vram = specs["total_vram_mb"]
        ram = specs["available_ram_gb"]

        has_ollama = engines["ollama"]["available"] and len(engines["ollama"]["models"]) > 0

        if has_ollama and vram >= 6000:
            return {
                "preferred_tier": "LOCAL",
                "recommended_engine": "ollama",
                "reason": f"Sufficient dedicated GPU VRAM ({vram}MB) and Ollama running with {engines['ollama']['models']}",
                "model_candidate": engines["ollama"]["models"][0]
            }
        elif has_ollama and ram >= 8.0:
            return {
                "preferred_tier": "HYBRID",
                "recommended_engine": "ollama_cpu",
                "reason": f"Ollama available on CPU with {ram}GB available RAM; recommended for offline privacy tasks",
                "model_candidate": engines["ollama"]["models"][0]
            }
        else:
            return {
                "preferred_tier": "CLOUD",
                "recommended_engine": "gemini_or_claude",
                "reason": "Cloud models recommended for high reasoning quality and low latency on host hardware",
                "model_candidate": "gemini-2.5-flash"
            }


_GLOBAL_PROFILER = None

def get_hardware_profiler() -> HardwareProfiler:
    global _GLOBAL_PROFILER
    if _GLOBAL_PROFILER is None:
        _GLOBAL_PROFILER = HardwareProfiler()
    return _GLOBAL_PROFILER
