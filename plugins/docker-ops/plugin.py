"""Docker Operations Plugin for Helm.

Inspect containers, stream logs, and restart services directly from Helm.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List

logger = logging.getLogger("helm.plugins.docker")


def docker_ps() -> Dict[str, Any]:
    """Lists currently active or all Docker containers."""
    try:
        cmd = ["docker", "ps", "--format", "{{json .}}"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, timeout=8)
        containers = []
        for line in output.strip().splitlines():
            if line:
                try:
                    c = json.loads(line)
                    containers.append({
                        "id": c.get("ID"),
                        "image": c.get("Image"),
                        "name": c.get("Names"),
                        "status": c.get("Status"),
                        "ports": c.get("Ports"),
                    })
                except Exception:
                    pass
        return {"status": "success", "containers_count": len(containers), "containers": containers}
    except FileNotFoundError:
        return {"status": "error", "error": "Docker executable not found on system PATH."}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error": f"Docker command failed: {e.stderr.strip() if e.stderr else str(e)}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def docker_logs(container_id: str) -> Dict[str, Any]:
    """Retrieves recent logs for a specific container."""
    if not container_id:
        return {"status": "error", "error": "container_id is required"}
    try:
        cmd = ["docker", "logs", "--tail", "50", container_id]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=10)
        return {
            "status": "success",
            "container_id": container_id,
            "logs": output[-2000:],  # Return latest 2KB
        }
    except Exception as e:
        return {"status": "error", "container_id": container_id, "error": str(e)}


def docker_restart_container(container_id: str) -> Dict[str, Any]:
    """Restarts a specified Docker container."""
    if not container_id:
        return {"status": "error", "error": "container_id is required"}
    try:
        cmd = ["docker", "restart", container_id]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, timeout=20)
        return {"status": "success", "container_id": container_id, "restarted": output.strip()}
    except Exception as e:
        return {"status": "error", "container_id": container_id, "error": str(e)}
