import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. Update homie_supervisor.py with PID create_time validation
sup_file = os.path.join(BASE_DIR, "homie_supervisor.py")
with open(sup_file, "r", encoding="utf-8") as f:
    sup = f.read()

target_reg_init = """        self.protected_pids: set[int] = {os.getpid()}
        self.registered_ui_pids: set[int] = set()"""

replacement_reg_init = """        self.protected_pids: set[int] = {os.getpid()}
        self.registered_ui_pids: dict[int, float] = {}  # PID -> create_time mapping for recycled-PID defense"""

assert target_reg_init in sup, "target_reg_init not found"
sup = sup.replace(target_reg_init, replacement_reg_init, 1)

# Add is_ui_pid_valid method to PolicySupervisor
target_method_anchor = """    def register_protected_pid(self, pid: int) -> None:
        \"\"\"Registers a trusted client PID (such as the UI process) to protect against synthetic injection.\"\"\"
        if isinstance(pid, int) and pid > 0:
            self.protected_pids.add(pid)
            logger.info("Supervisor registered protected PID: %d", pid)"""

replacement_method_anchor = """    def register_protected_pid(self, pid: int) -> None:
        \"\"\"Registers a trusted client PID (such as the UI process) to protect against synthetic injection.\"\"\"
        if isinstance(pid, int) and pid > 0:
            self.protected_pids.add(pid)
            logger.info("Supervisor registered protected PID: %d", pid)

    def is_ui_pid_valid(self, pid: int) -> bool:
        \"\"\"Verifies that the attested PID is in registered_ui_pids and matches the recorded process creation time.
        Rejects recycled PIDs that were assigned to newly spawned processes after original UI exited.
        \"\"\"
        import psutil
        with self._lock:
            if pid not in self.registered_ui_pids:
                return False
            try:
                proc = psutil.Process(pid)
                recorded_time = self.registered_ui_pids[pid]
                if abs(proc.create_time() - recorded_time) < 0.1:
                    return True
                else:
                    logger.warning("Rejected recycled PID %d: create_time %f != recorded %f", pid, proc.create_time(), recorded_time)
                    self.registered_ui_pids.pop(pid, None)
                    return False
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.registered_ui_pids.pop(pid, None)
                return False"""

assert target_method_anchor in sup, "target_method_anchor not found"
sup = sup.replace(target_method_anchor, replacement_method_anchor, 1)

# In _handle_register_ui: record create_time
target_handle_reg = """        # Prune dead PIDs to prevent PID recycling vulnerabilities
        self.protected_pids = {p for p in self.protected_pids if psutil.pid_exists(p)}
        self.registered_ui_pids = {p for p in self.registered_ui_pids if psutil.pid_exists(p)}
        self.registered_ui_pids.add(attested_pid)
        self.register_protected_pid(attested_pid)"""

replacement_handle_reg = """        # Prune dead PIDs and record create_time to prevent PID recycling vulnerabilities
        self.protected_pids = {p for p in self.protected_pids if psutil.pid_exists(p)}
        proc = psutil.Process(attested_pid)
        with self._lock:
            self.registered_ui_pids[attested_pid] = proc.create_time()
            self.register_protected_pid(attested_pid)"""

assert target_handle_reg in sup, "target_handle_reg not found"
sup = sup.replace(target_handle_reg, replacement_handle_reg, 1)

# In _handle_confirm: check is_ui_pid_valid
target_handle_chk = """        # 1. Kernel-attested PID role enforcement: MSG_CONFIRM accepted ONLY from registered UI
        if client_pid is not None:
            import psutil
            self.registered_ui_pids = {p for p in self.registered_ui_pids if psutil.pid_exists(p)}
            if client_pid not in self.registered_ui_pids:
                logger.warning("Rejected MSG_CONFIRM from un-attested PID %d (not in registered UI PIDs %s)", client_pid, self.registered_ui_pids)
                return self._encode_reply(MSG_ERROR, {
                    "error": f"DENIED: Confirmation rejected from untrusted PID {client_pid}. Only registered UI process can submit confirmation.",
                    "reason_code": REASON_UNAUTHORIZED_TOKEN
                })"""

replacement_handle_chk = """        # 1. Kernel-attested PID role enforcement: MSG_CONFIRM accepted ONLY from registered UI with matching create_time
        if client_pid is not None:
            if not self.is_ui_pid_valid(client_pid):
                logger.warning("Rejected MSG_CONFIRM from un-attested or recycled PID %d", client_pid)
                return self._encode_reply(MSG_ERROR, {
                    "error": f"DENIED: Confirmation rejected from untrusted or recycled PID {client_pid}. Only verified UI process can submit confirmation.",
                    "reason_code": REASON_UNAUTHORIZED_TOKEN
                })"""

assert target_handle_chk in sup, "target_handle_chk not found"
sup = sup.replace(target_handle_chk, replacement_handle_chk, 1)

with open(sup_file, "w", encoding="utf-8") as f:
    f.write(sup)
print("Updated homie_supervisor.py with create_time verification successfully")
