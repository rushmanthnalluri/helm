import os, sys

BASE_DIR = r"D:\homie"

with open(os.path.join(BASE_DIR, "app.py"), "r", encoding="utf-8") as f:
    app_code = f.read()

# 1. Update __init__
old_init = """class HomieApp:
    def __init__(self):
        self.prefs = homie.get_prefs()"""

new_init = """class HomieApp:
    def __init__(self, supervisor_pipe: str = r"\\\\.\\pipe\\homie_supervisor"):
        self.supervisor_pipe = supervisor_pipe
        self.prefs = homie.get_prefs()"""

assert old_init in app_code, "old_init not found in app.py"
app_code = app_code.replace(old_init, new_init)

# 2. Add pipe client registration and confined worker spawn to HomieApp.__init__
old_init_end = """        self.tray = None
        self.telegram = None"""

new_init_end = """        self.tray = None
        self.telegram = None

        # Connect to Policy Supervisor daemon over Named Pipe
        self.pipe_client = None
        try:
            import homie_supervisor
            self.pipe_client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=self.supervisor_pipe)
            if self.pipe_client.connect(timeout_sec=0.5):
                token = None
                token_path = os.path.join(BASE_DIR, ".homie_session.token")
                if os.path.exists(token_path):
                    with open(token_path, "r", encoding="utf-8") as tf:
                        token = tf.read().strip()
                res = self.pipe_client.register_ui(os.getpid(), session_token=token)
                print(f"[App] Connected to supervisor pipe (PID {os.getpid()}), registration: {res.get('status')}")
        except Exception as e:
            print(f"[App] Supervisor pipe connection: {e}")

        # Spawn AppContainer confined worker inside Job Object
        self._worker_hproc = None
        self._worker_pid = None
        self._worker_job = None
        try:
            import homie_confinement
            server_h, client_h, _ = homie_confinement.make_ipc_pair()
            worker_script = os.path.join(BASE_DIR, "homie_worker.py")
            hproc, w_pid, job = homie_confinement.spawn_confined_worker(
                [worker_script, "--pipe", self.supervisor_pipe],
                client_h
            )
            self._worker_hproc = hproc
            self._worker_pid = w_pid
            self._worker_job = job
            print(f"[App] Confined worker spawned successfully: PID {w_pid}")
        except Exception as e:
            print(f"[App] Confined worker spawn info: {e}")"""

assert old_init_end in app_code, "old_init_end not found in app.py"
app_code = app_code.replace(old_init_end, new_init_end)

# 3. Add clean shutdown in on_closed event and main argument parsing
old_main = """def main():
    app = HomieApp()
    app.run()"""

new_main = """def main():
    import argparse
    parser = argparse.ArgumentParser(description="Homie Desktop UI")
    parser.add_argument("--supervisor-pipe", default=r"\\\\.\\pipe\\homie_supervisor", help="Supervisor named pipe")
    parsed, _ = parser.parse_known_args()
    app = HomieApp(supervisor_pipe=parsed.supervisor_pipe)
    app.run()"""

assert old_main in app_code, "old_main not found in app.py"
app_code = app_code.replace(old_main, new_main)

# 4. Add window.events.closed hook
old_events = "        self.window.events.loaded += on_loaded"
new_events = """        self.window.events.loaded += on_loaded

        def on_closed():
            if hasattr(self, '_worker_job') and self._worker_job:
                try:
                    import win32api
                    win32api.CloseHandle(self._worker_job)
                except Exception:
                    pass
            if hasattr(self, 'pipe_client') and self.pipe_client:
                try:
                    self.pipe_client.close()
                except Exception:
                    pass

        self.window.events.closed += on_closed"""

assert old_events in app_code, "old_events not found in app.py"
app_code = app_code.replace(old_events, new_events)

with open(os.path.join(BASE_DIR, "app.py"), "w", encoding="utf-8") as f:
    f.write(app_code)
print("app.py patched [OK]")
