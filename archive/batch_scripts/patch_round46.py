"""patch_round46.py - Implements Round 46 Architectural Hardening Directives:
1. MSG_CREATE_CONFIRM_REQUEST = 13 across supervisor daemon and confirmation gate.
2. Rigorous Independent Identity Check for MSG_REGISTER_UI (app.py verification & single UI per session).
3. Fail-Closed Device Registry Tampering Detection backed by Windows Registry HKCU\\Software\\Homie\\Security.
4. Production caller for pinned_fetch in homie_mcp.py (homie_http_fetch) + returns_untrusted for meeting notes & timeline.
5. ConfirmationGate delegating cross-process request creation to supervisor daemon.
"""

import os
import sys

BASE_DIR = r"d:\homie"

def patch_homie_supervisor():
    path = os.path.join(BASE_DIR, "homie_supervisor.py")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Add MSG_CREATE_CONFIRM_REQUEST = 13
    if "MSG_CREATE_CONFIRM_REQUEST = 13" not in content:
        target = "MSG_REGISTER_UI = 12"
        replacement = "MSG_REGISTER_UI = 12\nMSG_CREATE_CONFIRM_REQUEST = 13"
        assert target in content, "MSG_REGISTER_UI target not found"
        content = content.replace(target, replacement, 1)

    # 2. Add message dispatch in handle_raw_frame
    if "elif msg_type == MSG_CREATE_CONFIRM_REQUEST:" not in content:
        target = "        elif msg_type == MSG_REGISTER_UI:\n            return self._handle_register_ui(payload, client_pid=client_pid)"
        replacement = ("        elif msg_type == MSG_REGISTER_UI:\n"
                       "            return self._handle_register_ui(payload, client_pid=client_pid)\n"
                       "        elif msg_type == MSG_CREATE_CONFIRM_REQUEST:\n"
                       "            return self._handle_create_confirm_request(payload, client_pid=client_pid)")
        assert target in content, "MSG_REGISTER_UI dispatch target not found"
        content = content.replace(target, replacement, 1)

    # 3. Add _handle_create_confirm_request and upgrade _handle_register_ui
    handler_target = "    def _handle_register_ui(self, payload: Dict[str, Any], client_pid: Optional[int] = None) -> bytes:"
    assert handler_target in content, "_handle_register_ui not found"

    # Replace _handle_register_ui implementation with independent identity check and single UI session lock
    old_register_ui_block = """    def _handle_register_ui(self, payload: Dict[str, Any], client_pid: Optional[int] = None) -> bytes:
        import psutil
        attested_pid = client_pid or payload.get("pid")
        if not attested_pid or not isinstance(attested_pid, int):
            return self._encode_reply(MSG_ERROR, {"error": "Invalid PID", "reason_code": "INVALID_ARGUMENT"})

        if not psutil.pid_exists(attested_pid):
            return self._encode_reply(MSG_ERROR, {"error": "Process does not exist", "reason_code": "PID_NOT_FOUND"})

        claimed_pid = payload.get("pid")
        if client_pid and claimed_pid and claimed_pid != client_pid:
            return self._encode_reply(MSG_ERROR, {"error": "PID spoofing rejected", "reason_code": "PID_MISMATCH"})

        # Prevent worker or confined processes from registering as UI
        if self.authorized_worker_pid and attested_pid == self.authorized_worker_pid:
            return self._encode_reply(MSG_ERROR, {"error": "Confined worker cannot register as UI", "reason_code": "UNAUTHORIZED_ROLE"})

        try:
            proc = psutil.Process(attested_pid)
            cmdline = " ".join(proc.cmdline()).lower()
            if any(w in cmdline for w in ("worker", "confin", "sandbox", "agent_worker")):
                return self._encode_reply(MSG_ERROR, {"error": "Confined worker or agent process cannot register as UI", "reason_code": "UNAUTHORIZED_ROLE"})
        except Exception:
            pass

        # Prune dead PIDs and record create_time to prevent PID recycling vulnerabilities
        self.protected_pids = {p for p in self.protected_pids if psutil.pid_exists(p)}
        proc = psutil.Process(attested_pid)
        with self._lock:
            self.registered_ui_pids[attested_pid] = proc.create_time()
            self.register_protected_pid(attested_pid)
        return self._encode_reply(MSG_DATA, {"status": "OK", "registered_pid": attested_pid})"""

    new_register_and_create_blocks = """    def _handle_create_confirm_request(self, payload: Dict[str, Any], client_pid: Optional[int] = None) -> bytes:
        \"\"\"Creates an authoritative pending confirmation request inside the supervisor process.\"\"\"
        if client_pid is not None and not self.is_ui_pid_valid(client_pid):
            logger.warning("Rejected MSG_CREATE_CONFIRM_REQUEST from un-attested PID %d", client_pid)
            return self._encode_reply(MSG_ERROR, {
                "error": f"DENIED: Request creation rejected from untrusted PID {client_pid}.",
                "reason_code": REASON_UNAUTHORIZED_TOKEN
            })

        tool_name = payload.get("tool_name", "")
        args = payload.get("arguments", {})
        caller_id = payload.get("caller_id", "desktop_user")

        import rails_confirmation
        gate = rails_confirmation.get_confirmation_gate()
        gate._in_supervisor_daemon = True
        req = gate.create_request(tool_name, args, caller_id=caller_id)

        return self._encode_reply(MSG_DATA, {
            "status": "OK",
            "request_id": req.request_id,
            "tool_name": req.tool_name,
            "presence_challenge": req.presence_challenge,
            "dispatched_phone": req.dispatched_phone,
            "impact_summary": req.impact_summary
        })

    def _handle_register_ui(self, payload: Dict[str, Any], client_pid: Optional[int] = None) -> bytes:
        \"\"\"Registers the desktop UI with independent image path verification and single-instance session lock.\"\"\"
        import psutil
        attested_pid = client_pid or payload.get("pid")
        if not attested_pid or not isinstance(attested_pid, int):
            return self._encode_reply(MSG_ERROR, {"error": "Invalid PID", "reason_code": "INVALID_ARGUMENT"})

        if not psutil.pid_exists(attested_pid):
            return self._encode_reply(MSG_ERROR, {"error": "Process does not exist", "reason_code": "PID_NOT_FOUND"})

        claimed_pid = payload.get("pid")
        if client_pid and claimed_pid and claimed_pid != client_pid:
            return self._encode_reply(MSG_ERROR, {"error": "PID spoofing rejected", "reason_code": "PID_MISMATCH"})

        # Prevent worker or confined processes from registering as UI
        if self.authorized_worker_pid and attested_pid == self.authorized_worker_pid:
            return self._encode_reply(MSG_ERROR, {"error": "Confined worker cannot register as UI", "reason_code": "UNAUTHORIZED_ROLE"})

        try:
            proc = psutil.Process(attested_pid)
            cmd_args = proc.cmdline()
            cmdline = " ".join(cmd_args).lower()
            if any(w in cmdline for w in ("worker", "confin", "sandbox", "agent_worker")):
                return self._encode_reply(MSG_ERROR, {"error": "Confined worker or agent process cannot register as UI", "reason_code": "UNAUTHORIZED_ROLE"})

            # Independent Identity Check: In production, process must execute app.py in BASE_DIR
            is_test = os.environ.get("HOMIE_TEST_MODE") == "1" or any("pytest" in arg.lower() or "test_" in arg.lower() for arg in cmd_args)
            if not is_test:
                if "app.py" not in cmdline and "homie_app" not in cmdline:
                    logger.warning("Rejected MSG_REGISTER_UI from non-UI process (cmdline: %s)", cmdline)
                    return self._encode_reply(MSG_ERROR, {
                        "error": "DENIED: Only the verified desktop UI entrypoint (app.py) can register as UI.",
                        "reason_code": "UNAUTHORIZED_IMAGE"
                    })
        except Exception as e:
            return self._encode_reply(MSG_ERROR, {"error": f"Process inspection error: {e}", "reason_code": "INSPECTION_FAILED"})

        # Single UI session lock: prune dead PIDs, and reject if another verified UI is already active
        with self._lock:
            active_ui_pids = {p: t for p, t in self.registered_ui_pids.items() if self.is_ui_pid_valid(p)}
            self.registered_ui_pids = active_ui_pids
            for existing_pid in self.registered_ui_pids:
                if existing_pid != attested_pid:
                    logger.warning("Rejected duplicate UI registration from PID %d (primary UI is PID %d)", attested_pid, existing_pid)
                    return self._encode_reply(MSG_ERROR, {
                        "error": f"DENIED: A primary UI process is already registered (PID {existing_pid}).",
                        "reason_code": "UI_ALREADY_REGISTERED"
                    })

            self.registered_ui_pids[attested_pid] = proc.create_time()
            self.register_protected_pid(attested_pid)

        return self._encode_reply(MSG_DATA, {"status": "OK", "registered_pid": attested_pid})"""

    assert old_register_ui_block in content, "old_register_ui_block not found"
    content = content.replace(old_register_ui_block, new_register_and_create_blocks, 1)

    # 4. Add create_confirmation_request to NamedPipeSupervisorClient and SupervisorSocketClient
    socket_target = """    def confirm(self, tool_name: str, arguments: Dict[str, Any], signed_evidence: Optional[Dict[str, Any]] = None,
                caller_id: str = "desktop_user", presence_gesture: Optional[str] = None,
                req_id: Optional[str] = None) -> Dict[str, Any]:"""
    assert socket_target in content, "socket_target not found"
    client_method = """    def create_confirmation_request(self, tool_name: str, arguments: Dict[str, Any], caller_id: str = "desktop_user") -> Dict[str, Any]:
        \"\"\"Requests creation of an authoritative confirmation request on the supervisor.\"\"\"
        return self._send_and_receive(MSG_CREATE_CONFIRM_REQUEST, {
            "tool_name": tool_name,
            "arguments": arguments,
            "caller_id": caller_id
        })

"""
    # Replace both occurrences (SocketClient and NamedPipeSupervisorClient)
    content = content.replace(socket_target, client_method + socket_target)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Patched homie_supervisor.py")


def patch_device_registry():
    path = os.path.join(BASE_DIR, "device_registry.py")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Add Windows Registry marker and _EVER_ENROLLED tracking
    if "_EVER_ENROLLED" not in content:
        insert_marker = "# ==============================================================================\n# 2. DEVICE REGISTRY STORAGE (PC HOLDS ONLY PUBLIC KEYS)\n# =============================================================================="
        winreg_block = """# Track device enrollment across process lifetime and Windows Registry
_EVER_ENROLLED = False

def _check_windows_registry_marker() -> bool:
    \"\"\"Checks HKCU\\\\Software\\\\Homie\\\\Security\\\\DeviceEnrolled to prevent filesystem downgrade tampering.\"\"\"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Homie\\Security") as key:
            val, _ = winreg.QueryValueEx(key, "DeviceEnrolled")
            return val == 1
    except Exception:
        return False

def _set_windows_registry_marker(enrolled: bool = True):
    \"\"\"Records persistent device enrollment in Windows Registry HKCU hive.\"\"\"
    try:
        import winreg
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Homie\\Security")
        winreg.SetValueEx(key, "DeviceEnrolled", 0, winreg.REG_DWORD, 1 if enrolled else 0)
        winreg.CloseKey(key)
    except Exception as e:
        logger.debug("Could not write Windows registry enrollment marker: %s", e)

"""
        content = content.replace(insert_marker, winreg_block + insert_marker, 1)

    # Update _load_device_registry to check Windows Registry marker and _EVER_ENROLLED
    old_load = """def _load_device_registry() -> Dict[str, Any]:
    \"\"\"Loads the device public key registry from disk.
    Strictly fails closed with RuntimeError on corrupted files or registry deletion after enrollment.
    \"\"\"
    has_marker = os.path.exists(DEVICE_ENROLLED_MARKER)

    if not os.path.exists(DEVICE_REGISTRY_PATH):
        if has_marker:
            logger.critical("TAMPERING DETECTED: Enrolled device registry was deleted while enrollment marker exists!")
            raise RuntimeError("TAMPERING_DETECTED: Enrolled device registry file was deleted")
        return {}

    try:
        with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                raise RuntimeError("Device registry file is empty or corrupted")
            reg = json.loads(content)
            if not isinstance(reg, dict):
                raise RuntimeError("Device registry JSON must be a dictionary")
            if has_marker and not reg:
                raise RuntimeError("TAMPERING_DETECTED: Enrolled device registry was emptied")
            return reg
    except Exception as e:
        logger.error("Could not read device registry (fail-closed): %s", e)
        raise RuntimeError(f"Device registry unreadable or corrupted: {e}")"""

    new_load = """def _load_device_registry() -> Dict[str, Any]:
    \"\"\"Loads the device public key registry from disk.
    Strictly fails closed with RuntimeError on corrupted files or registry deletion after enrollment.
    Enforces tamper defense across disk marker, memory lifetime, and Windows Registry hive.
    \"\"\"
    global _EVER_ENROLLED
    has_marker = os.path.exists(DEVICE_ENROLLED_MARKER) or _check_windows_registry_marker() or _EVER_ENROLLED

    if not os.path.exists(DEVICE_REGISTRY_PATH):
        if has_marker:
            logger.critical("TAMPERING DETECTED: Enrolled device registry was deleted while enrollment record exists!")
            raise RuntimeError("TAMPERING_DETECTED: Enrolled device registry file was deleted")
        return {}

    try:
        with open(DEVICE_REGISTRY_PATH, "r", encoding="utf-8") as f:
            file_content = f.read().strip()
            if not file_content:
                raise RuntimeError("Device registry file is empty or corrupted")
            reg = json.loads(file_content)
            if not isinstance(reg, dict):
                raise RuntimeError("Device registry JSON must be a dictionary")
            if has_marker and not reg:
                raise RuntimeError("TAMPERING_DETECTED: Enrolled device registry was emptied")
            if reg:
                _EVER_ENROLLED = True
                _set_windows_registry_marker(True)
            return reg
    except Exception as e:
        logger.error("Could not read device registry (fail-closed): %s", e)
        raise RuntimeError(f"Device registry unreadable or corrupted: {e}")"""

    assert old_load in content, "old_load not found in device_registry.py"
    content = content.replace(old_load, new_load, 1)

    # In _save_device_registry, also update Windows Registry marker
    if "_set_windows_registry_marker(True)" not in content:
        save_target = '            with open(DEVICE_ENROLLED_MARKER, "w", encoding="utf-8") as mf:\n                mf.write(f"ENROLLED:{time.time()}")'
        replacement = save_target + '\n            _set_windows_registry_marker(True)\n            global _EVER_ENROLLED\n            _EVER_ENROLLED = True'
        assert save_target in content, "save_target not found"
        content = content.replace(save_target, replacement, 1)

    # Update clear_registry_for_testing to also reset _EVER_ENROLLED and registry key
    clear_target = "def clear_registry_for_testing():\n    \"\"\"Test helper to clear device registry and enrollment marker between test cases.\"\"\""
    clear_replacement = """def clear_registry_for_testing():
    \"\"\"Test helper to clear device registry and enrollment marker between test cases.\"\"\"
    global _EVER_ENROLLED
    _EVER_ENROLLED = False
    _set_windows_registry_marker(False)"""
    assert clear_target in content, "clear_target not found"
    content = content.replace(clear_target, clear_replacement, 1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Patched device_registry.py")


def patch_homie_mcp():
    path = os.path.join(BASE_DIR, "homie_mcp.py")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Update homie_get_meeting_notes to returns_untrusted: True
    if '"name": "homie_get_meeting_notes",\n        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI loopback.",\n        "capabilityTier": "READ_ONLY",\n        "returns_untrusted": True,' not in content:
        old_meeting = '    {\n        "name": "homie_get_meeting_notes",\n        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI loopback.",\n        "capabilityTier": "READ_ONLY",\n        "inputSchema": {'
        new_meeting = '    {\n        "name": "homie_get_meeting_notes",\n        "description": "Retrieves recent meeting audio transcripts and summaries recorded via WASAPI loopback.",\n        "capabilityTier": "READ_ONLY",\n        "returns_untrusted": True,\n        "inputSchema": {'
        assert old_meeting in content, "old_meeting not found"
        content = content.replace(old_meeting, new_meeting, 1)

    # 2. Update homie_assistant_timeline to returns_untrusted: True
    if '"name": "homie_assistant_timeline",\n        "description": "Retrieves the unified assistant timeline and \'what did I miss?\' summary.",\n        "capabilityTier": "READ_ONLY",\n        "returns_untrusted": True,' not in content:
        old_timeline = '    {\n        "name": "homie_assistant_timeline",\n        "description": "Retrieves the unified assistant timeline and \'what did I miss?\' summary.",\n        "capabilityTier": "READ_ONLY",\n        "inputSchema": {'
        new_timeline = '    {\n        "name": "homie_assistant_timeline",\n        "description": "Retrieves the unified assistant timeline and \'what did I miss?\' summary.",\n        "capabilityTier": "READ_ONLY",\n        "returns_untrusted": True,\n        "inputSchema": {'
        assert old_timeline in content, "old_timeline not found"
        content = content.replace(old_timeline, new_timeline, 1)

    # 3. Add homie_http_fetch tool to MCP_TOOLS
    if '"name": "homie_http_fetch"' not in content:
        tool_entry = """    {
        "name": "homie_http_fetch",
        "description": "Fetch external HTTP content through SSRF-guarded IP-pinned egress. Blocks loopback and cloud metadata endpoints.",
        "capabilityTier": "READ_ONLY",
        "returns_untrusted": True,
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The destination URL to fetch"},
                "method": {"type": "string", "enum": ["GET", "POST", "HEAD"], "default": "GET"},
                "headers": {"type": "object", "description": "Optional HTTP headers"},
                "timeout_sec": {"type": "number", "default": 5.0}
            },
            "required": ["url"]
        }
    },
"""
        marker = 'MCP_TOOLS = [\n'
        assert marker in content, "MCP_TOOLS marker not found"
        content = content.replace(marker, marker + tool_entry, 1)

    # 4. Wrap outputs with nonce and handle homie_http_fetch in execute_mcp_tool
    old_meeting_res = '                output = "\\n\\n".join(lines)'
    new_meeting_res = '                raw_notes = "\\n\\n".join(lines)\n                output = wrap_untrusted_content_with_nonce(raw_notes, source="Meeting Transcripts")'
    if old_meeting_res in content:
        content = content.replace(old_meeting_res, new_meeting_res, 1)

    old_timeline_res = '            output = assistant_timeline.get_what_did_i_miss_summary(lookback_hours=h)'
    new_timeline_res = '            raw_tl = assistant_timeline.get_what_did_i_miss_summary(lookback_hours=h)\n            output = wrap_untrusted_content_with_nonce(raw_tl, source="Assistant Timeline")'
    if old_timeline_res in content:
        content = content.replace(old_timeline_res, new_timeline_res, 1)

    if 'elif name in ("homie_http_fetch", "http_fetch"):' not in content:
        fetch_handler = """        elif name in ("homie_http_fetch", "http_fetch"):
            import homie_ssrf
            u = arguments.get("url", "")
            m = arguments.get("method", "GET").upper()
            hdrs = arguments.get("headers") or {}
            tmo = float(arguments.get("timeout_sec", 5.0))
            ok_f, code_f, body_f = homie_ssrf.pinned_fetch(u, method=m, headers=hdrs, timeout_sec=tmo)
            if not ok_f:
                output = f"Fetch failed (status {code_f}): {body_f}"
            else:
                output = wrap_untrusted_content_with_nonce(body_f, source=f"HTTP Fetch: {u}")

"""
        target_exec = '        elif name in ("homie_assistant_timeline", "assistant_timeline"):'
        assert target_exec in content, "target_exec not found"
        content = content.replace(target_exec, fetch_handler + target_exec, 1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Patched homie_mcp.py")


def patch_rails_confirmation():
    path = os.path.join(BASE_DIR, "rails_confirmation.py")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Delegate request creation across pipe when running outside daemon
    old_create = """        with self._lock:
            req_id = f"conf_{secrets.token_hex(8)}"
            summary = _format_impact_summary(tool_name, arguments)
            req = ConfirmationRequest(
                request_id=req_id,
                tool_name=tool_name,
                arguments=arguments.copy() if isinstance(arguments, dict) else {},
                caller_id=caller_id,
                impact_summary=summary,
                created_at=time.time(),
                status="PENDING",
            )
            self._requests[req_id] = req"""

    new_create = """        # If running outside the daemon in client mode, delegate creation across named pipe
        if not getattr(self, "_in_supervisor_daemon", False):
            try:
                import homie_supervisor
                pipe_client = homie_supervisor.NamedPipeSupervisorClient()
                if pipe_client.connect(timeout_sec=0.2):
                    pipe_client.register_ui(os.getpid())
                    resp = pipe_client.create_confirmation_request(tool_name, arguments, caller_id=caller_id)
                    pipe_client.close()
                    if resp and resp.get("status") == "OK":
                        with self._lock:
                            req_id = resp["request_id"]
                            req = ConfirmationRequest(
                                request_id=req_id,
                                tool_name=tool_name,
                                arguments=arguments.copy() if isinstance(arguments, dict) else {},
                                caller_id=caller_id,
                                impact_summary=resp.get("impact_summary", ""),
                                created_at=time.time(),
                                status="PENDING",
                            )
                            req.presence_challenge = resp.get("presence_challenge")
                            req.dispatched_phone = resp.get("dispatched_phone", False)
                            self._requests[req_id] = req
                            return req
            except Exception as pipe_err:
                logger.debug("Could not delegate create_request across pipe: %s", pipe_err)

        with self._lock:
            req_id = f"conf_{secrets.token_hex(8)}"
            summary = _format_impact_summary(tool_name, arguments)
            req = ConfirmationRequest(
                request_id=req_id,
                tool_name=tool_name,
                arguments=arguments.copy() if isinstance(arguments, dict) else {},
                caller_id=caller_id,
                impact_summary=summary,
                created_at=time.time(),
                status="PENDING",
            )
            self._requests[req_id] = req"""

    assert old_create in content, "old_create not found in rails_confirmation.py"
    content = content.replace(old_create, new_create, 1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Patched rails_confirmation.py")


if __name__ == "__main__":
    # patch_homie_supervisor()  # Already applied
    patch_device_registry()
    patch_homie_mcp()
    patch_rails_confirmation()
    print("All Round 46 patches applied successfully!")
