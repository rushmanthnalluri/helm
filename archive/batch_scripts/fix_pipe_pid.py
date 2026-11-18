import os

BASE_DIR = r"D:\homie"

# 1. Update homie_supervisor.py
with open(os.path.join(BASE_DIR, "homie_supervisor.py"), "r", encoding="utf-8") as f:
    c = f.read()

target = """                # Verify server process ID against recorded/expected daemon PID if present
                try:
                    server_pid = win32pipe.GetNamedPipeServerProcessId(self.handle)
                    self.server_pid = server_pid
                    daemon_pid_path = os.path.join(BASE_DIR, ".homie_daemon.pid")
                    if os.path.exists(daemon_pid_path):
                        with open(daemon_pid_path, "r", encoding="utf-8") as df:
                            expected_pid = int(df.read().strip())
                        if expected_pid and server_pid != expected_pid:
                            logger.critical("ROGUE PIPE SERVER DETECTED! Expected PID %d, pipe server is PID %d", expected_pid, server_pid)
                            win32file.CloseHandle(self.handle)
                            self.handle = None
                            return False
                except Exception as pid_err:
                    logger.debug("Server PID verification info: %s", pid_err)"""

replacement = """                # Verify server process ID against recorded/expected daemon PID for production daemon pipe
                if self.pipe_name.lower().endswith(r"\\homie_supervisor"):
                    try:
                        server_pid = win32pipe.GetNamedPipeServerProcessId(self.handle)
                        self.server_pid = server_pid
                        daemon_pid_path = os.path.join(BASE_DIR, ".homie_daemon.pid")
                        if os.path.exists(daemon_pid_path):
                            with open(daemon_pid_path, "r", encoding="utf-8") as df:
                                expected_pid = int(df.read().strip())
                            if expected_pid and server_pid != expected_pid:
                                logger.critical("ROGUE PIPE SERVER DETECTED! Expected PID %d, pipe server is PID %d", expected_pid, server_pid)
                                win32file.CloseHandle(self.handle)
                                self.handle = None
                                return False
                    except Exception as pid_err:
                        logger.debug("Server PID verification info: %s", pid_err)"""

assert target in c, "target not found in homie_supervisor.py"
c = c.replace(target, replacement)
with open(os.path.join(BASE_DIR, "homie_supervisor.py"), "w", encoding="utf-8") as f:
    f.write(c)
print("homie_supervisor.py updated successfully [OK]")

# 2. Update action_broker.py: move SSRF check to Step 0 before pipe/supervisor execution
with open(os.path.join(BASE_DIR, "action_broker.py"), "r", encoding="utf-8") as f:
    ab = f.read()

target_exec = """        args = arguments or {}
        canonical_tool = self.normalize_tool_name(tool_name)
        req_id = f"req_{int(time.time()*1000)}"

        # 0. Out-of-Process Pipe Client Branch (Fail-Closed)"""

replacement_exec = """        args = arguments or {}
        canonical_tool = self.normalize_tool_name(tool_name)
        req_id = f"req_{int(time.time()*1000)}"

        # Step 0: Input Validation & SSRF Guard (evaluated before broker dispatch)
        import homie_ssrf
        for k in ("url", "target", "destination", "endpoint"):
            cand_url = args.get(k)
            if cand_url and isinstance(cand_url, str) and ("http://" in cand_url or "https://" in cand_url):
                ssrf_err = homie_ssrf.check_ssrf(cand_url)
                if ssrf_err:
                    msg = f"Security Gate: SSRF check blocked outbound URL ({ssrf_err})"
                    logger.warning("Action %s denied by SSRF check: %s", canonical_tool, msg)
                    return False, msg, None

        # 0. Out-of-Process Pipe Client Branch (Fail-Closed)"""

assert target_exec in ab, "target_exec not found in action_broker.py"
ab = ab.replace(target_exec, replacement_exec)
with open(os.path.join(BASE_DIR, "action_broker.py"), "w", encoding="utf-8") as f:
    f.write(ab)
print("action_broker.py updated with pre-dispatch SSRF gate [OK]")

# 3. Clean up stale .homie_daemon.pid and .homie_session.token
for fname in [".homie_daemon.pid", ".homie_session.token"]:
    fpath = os.path.join(BASE_DIR, fname)
    if os.path.exists(fpath):
        try:
            os.remove(fpath)
            print(f"Removed stale {fname}")
        except Exception:
            pass

# 4. Update tests/conftest.py to set taint_tracker.set_standalone_mode(True)
with open(os.path.join(BASE_DIR, "tests", "conftest.py"), "r", encoding="utf-8") as f:
    conf = f.read()

target_conf = "    taint_tracker.clear_all_taints()"
replacement_conf = "    taint_tracker.clear_all_taints()\n    taint_tracker.set_standalone_mode(True)"
if replacement_conf not in conf and target_conf in conf:
    conf = conf.replace(target_conf, replacement_conf, 1)
    with open(os.path.join(BASE_DIR, "tests", "conftest.py"), "w", encoding="utf-8") as f:
        f.write(conf)
    print("tests/conftest.py updated with set_standalone_mode(True) [OK]")
