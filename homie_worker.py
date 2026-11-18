"""homie_worker.py - Confined Agent Worker Process for Homie.

Runs inside the Windows AppContainer + Job Object sandbox spawned by homie_confinement.py:
- Zero direct network capabilities (kernel-enforced by AppContainer token).
- Communicates with parent UI/actuator via inherited duplex IPC pipe handle.
- Hardware-grade isolation: cannot tamper with supervisor memory, keys, or state.
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("homie.worker")

# Message type constants (mirroring supervisor protocol without importing privileged modules)
MSG_HELLO = 1
MSG_HELLO_ACK = 2
MSG_PROPOSE = 3
MSG_DECISION = 4
MSG_PROXY_LLM = 8


def main():
    parser = argparse.ArgumentParser(description="Homie Confined Worker")
    parser.add_argument("--pipe", default=r"\\.\pipe\homie_supervisor", help="Named pipe path")
    parser.add_argument("handle", nargs="?", default=None, help="Inherited pipe handle integer")
    args = parser.parse_args()

    handle_val = None
    if args.handle:
        try:
            import pywintypes
            handle_val = pywintypes.HANDLE(int(args.handle))
        except Exception:
            handle_val = None

    def read_req():
        if handle_val:
            try:
                import win32file
                hr, data = win32file.ReadFile(handle_val, 65536)
                if not data:
                    return None
                return data.decode("utf-8")
            except Exception:
                return None
        else:
            line = sys.stdin.readline()
            return line if line else None

    def write_resp(msg_dict):
        text = json.dumps(msg_dict)
        if handle_val:
            try:
                import win32file
                win32file.WriteFile(handle_val, (text + "\n").encode("utf-8"))
            except Exception:
                pass
        else:
            print(text)
            sys.stdout.flush()

    write_resp({"status": "READY", "pid": os.getpid(), "pipe": args.pipe})

    # Worker event loop: reads turn requests from pipe or stdin
    try:
        while True:
            raw = read_req()
            if not raw:
                break
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                    req_type = req.get("type")
                    if req_type == "ping":
                        write_resp({"type": "pong", "time": time.time()})
                    elif req_type == "propose":
                        tool = req.get("tool")
                        tool_args = req.get("args", {})
                        token = req.get("step_up_token")
                        res = {"status": "FORWARD_PARENT", "tool": tool, "args": tool_args, "token": token}
                        write_resp({"type": "propose_reply", "result": res})
                    elif req_type == "exit":
                        return
                except Exception as e:
                    write_resp({"type": "error", "error": str(e)})
    finally:
        pass


if __name__ == "__main__":
    main()
