import re

with open("homie_supervisor.py", "rb") as f:
    content = f.read().decode("utf-8")

old_init = """    def __init__(self, authorized_worker_pid: Optional[int] = None, state_db_path: Optional[str] = None):
        global _ACTIVE_SUPERVISOR
        _ACTIVE_SUPERVISOR = self
        self.authorized_worker_pid = authorized_worker_pid"""

new_init = """    def __init__(
        self,
        authorized_worker_pid: Optional[int] = None,
        state_db_path: Optional[str] = None,
        enforce_dirty_check: bool = True
    ):
        global _ACTIVE_SUPERVISOR
        _ACTIVE_SUPERVISOR = self
        self.authorized_worker_pid = authorized_worker_pid
        self.enforce_dirty_check = enforce_dirty_check"""

old_check = """        # Check dirty bit from previous run
        self._check_dirty_bit_on_startup()"""

new_check = """        # Check dirty bit from previous run
        if self.enforce_dirty_check:
            self._check_dirty_bit_on_startup()"""

crlf = "\r\n" in content
content_norm = content.replace("\r\n", "\n")

assert old_init in content_norm, "old_init not found"
assert old_check in content_norm, "old_check not found"

content_norm = content_norm.replace(old_init, new_init, 1)
content_norm = content_norm.replace(old_check, new_check, 1)

if crlf:
    final_content = content_norm.replace("\n", "\r\n")
else:
    final_content = content_norm

with open("homie_supervisor.py", "wb") as f:
    f.write(final_content.encode("utf-8"))

print("Successfully patched homie_supervisor.py")
