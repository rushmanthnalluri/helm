import os, sys

BASE_DIR = r"D:\homie"

# 2. Update action_broker.py
with open(os.path.join(BASE_DIR, "action_broker.py"), "r", encoding="utf-8") as f:
    ab_code = f.read()

target_ab = """        else:
            # Check if running in strict pipe mode / target architecture
            require_pipe = os.environ.get("HOMIE_REQUIRE_PIPE") == "1"
            is_test_env = os.environ.get("HOMIE_TEST_ENV") == "1"

            if require_pipe or not is_test_env:
                # Production / target architecture: STRICT PIPE CLIENT.
                # Process holds NO in-process supervisor, NO intent key, NO actuators!
                self.supervisor = None
                self.pipe_client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=self.pipe_name)
                self.client = self.pipe_client
                try:
                    if self.client.connect(timeout_sec=0.2):
                        self.client.register_ui(os.getpid())
                except Exception:
                    pass
            else:
                # In-memory test suite backward compatibility
                self.supervisor = homie_supervisor.PolicySupervisor()
                if self.supervisor.state != homie_supervisor.STATE_LOCKED:
                    self.supervisor.state = homie_supervisor.STATE_ARMED
                self.client = homie_supervisor.SupervisorClient(self.supervisor)
                self.client.connect()"""

replacement_ab = """        elif standalone_mode:
            # Explicit standalone in-process mode (zero test env flags)
            self.supervisor = homie_supervisor.PolicySupervisor()
            if self.supervisor.state != homie_supervisor.STATE_LOCKED:
                self.supervisor.state = homie_supervisor.STATE_ARMED
            self.client = homie_supervisor.SupervisorClient(self.supervisor)
            self.client.connect()
        else:
            # Production / target architecture: STRICT PIPE CLIENT.
            # Process holds NO in-process supervisor, NO intent key, NO actuators!
            self.supervisor = None
            self.pipe_client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=self.pipe_name)
            self.client = self.pipe_client
            try:
                if self.client.connect(timeout_sec=0.2):
                    self.client.register_ui(os.getpid())
            except Exception:
                pass"""

ab_code = ab_code.replace(
    'pipe_name: str = r"\\\\.\\pipe\\homie_supervisor"',
    'pipe_name: str = r"\\\\.\\pipe\\homie_supervisor",\n        standalone_mode: bool = False'
)

assert target_ab in ab_code, "target_ab not found in action_broker.py"
ab_code = ab_code.replace(target_ab, replacement_ab)

with open(os.path.join(BASE_DIR, "action_broker.py"), "w", encoding="utf-8") as f:
    f.write(ab_code)
print("action_broker.py patched [OK]")


# 3. Update step_up_gate.py
with open(os.path.join(BASE_DIR, "step_up_gate.py"), "r", encoding="utf-8") as f:
    sug_code = f.read()

old_sug = """def push_step_up_request_to_phone(step_up_id, session_id, tool_name, arguments, source="untrusted_content"):
    \"\"\"Pushes an interactive confirmation to the user's paired Telegram phone.\"\"\"
    if os.environ.get("HOMIE_TEST_ENV") == "1":
        return True, "Test environment: simulated step-up push"
    try:"""

new_sug = """def push_step_up_request_to_phone(step_up_id, session_id, tool_name, arguments, source="untrusted_content"):
    \"\"\"Pushes an interactive confirmation to the user's paired Telegram phone.\"\"\"
    try:"""

assert old_sug in sug_code, "old_sug not found in step_up_gate.py"
sug_code = sug_code.replace(old_sug, new_sug)

with open(os.path.join(BASE_DIR, "step_up_gate.py"), "w", encoding="utf-8") as f:
    f.write(sug_code)
print("step_up_gate.py patched [OK]")


# 4. Update worker_confinement.py
with open(os.path.join(BASE_DIR, "worker_confinement.py"), "r", encoding="utf-8") as f:
    wc_code = f.read()

old_wc = '        self.mock_mode = mock_mode or (os.environ.get("HOMIE_TEST_ENV") == "1")'
new_wc = '        self.mock_mode = mock_mode'

assert old_wc in wc_code, "old_wc not found in worker_confinement.py"
wc_code = wc_code.replace(old_wc, new_wc)

with open(os.path.join(BASE_DIR, "worker_confinement.py"), "w", encoding="utf-8") as f:
    f.write(wc_code)
print("worker_confinement.py patched [OK]")
