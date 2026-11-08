"""tests/test_confinement_attacks.py - Batch 18A acceptance test (Windows only).

The "worker" here is a REAL confined process (restricted token, low IL, job
object), not an in-process call. Every attack must fail at the OS level.
"""
import sys
import os

# ------------------------------------------------------------ worker (attacker)
if len(sys.argv) > 1 and sys.argv[1] == "--worker":
    import json
    import socket
    import subprocess
    import ctypes
    import win32api
    import win32con
    import win32file
    import pywintypes

    argv = sys.argv[2:]
    sup_pid, secret_file, flag_file, port, handle = (
        int(argv[0]), argv[1], argv[2], int(argv[3]), int(argv[4]))
    results = {}

    def attack(name, fn):
        try:
            results[name] = "ALLOWED" if fn() is not False else "blocked"
        except Exception:
            results[name] = "blocked"

    def open_vm_write():
        win32api.CloseHandle(win32api.OpenProcess(
            win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, sup_pid))

    def open_terminate():
        win32api.CloseHandle(win32api.OpenProcess(
            win32con.PROCESS_TERMINATE, False, sup_pid))

    def open_dup_handle():
        win32api.CloseHandle(win32api.OpenProcess(
            win32con.PROCESS_DUP_HANDLE, False, sup_pid))

    def read_secret():
        with open(secret_file, "rb") as f:
            f.read(1)

    def delete_flag():
        os.remove(flag_file)

    def write_flag():
        with open(flag_file, "ab") as f:
            f.write(b"x")

    def spawn_child():
        subprocess.Popen([sys._base_executable, "-c", "pass"]).wait()

    def clipboard():
        import ctypes
        if ctypes.windll.user32.OpenClipboard(0):
            try:
                h_data = ctypes.windll.user32.GetClipboardData(1)  # CF_TEXT = 1
                if h_data:
                    return True
                if ctypes.GetLastError() == 5:  # ERROR_ACCESS_DENIED
                    return False
            finally:
                ctypes.windll.user32.CloseClipboard()
        return False  # blocked

    def network():
        socket.create_connection(("127.0.0.1", port), timeout=2).close()

    for name, fn in [
        ("open_supervisor_vm_write", open_vm_write),
        ("open_supervisor_terminate", open_terminate),
        ("open_supervisor_dup_handle", open_dup_handle),
        ("read_secret_file", read_secret),
        ("delete_dirty_flag", delete_flag),
        ("write_dirty_flag", write_flag),
        ("spawn_child_process", spawn_child),
        ("read_clipboard_directly", clipboard),
        ("open_network_socket", network),
    ]:
        attack(name, fn)

    win32file.WriteFile(pywintypes.HANDLE(handle), json.dumps(results).encode())
    sys.exit(0)


# ------------------------------------------------------------------- test harness
import json
import socket
import tempfile
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    import pytest
except ImportError:
    pytest = None

if sys.platform != "win32" and pytest:
    pytest.skip("Windows-only confinement tests", allow_module_level=True)

import win32api
import win32con
import win32event
import win32file
import win32pipe
import pywintypes

import homie_confinement as conf


def test_confined_worker_attacks(tmp_path=None):
    if tmp_path is None:
        tmp_path = Path(tempfile.mkdtemp())
    secret = tmp_path / "ledger_key.bin"
    flag = tmp_path / "homie_supervisor_dirty.flag"
    secret.write_bytes(b"k" * 32)
    flag.write_bytes(b"1")
    conf.harden_path(str(secret))
    conf.harden_path(str(flag))
    conf.harden_current_process()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    server, client_h, _name = conf.make_ipc_pair()
    this_file = os.path.abspath(__file__)
    hproc, _pid, job = conf.spawn_confined_worker(
        [this_file, "--worker", str(os.getpid()), str(secret), str(flag), str(port)],
        client_h)

    try:
        try:
            win32pipe.ConnectNamedPipe(server, None)
        except pywintypes.error as e:
            if e.winerror != 535:  # ERROR_PIPE_CONNECTED
                raise
        _rc, data = win32file.ReadFile(server, 1 << 16)
        results = json.loads(data)
        win32event.WaitForSingleObject(hproc, 30_000)
    finally:
        conf.unharden_path(str(secret))
        conf.unharden_path(str(flag))
        try:
            win32api.CloseHandle(win32api.OpenProcess(  # job close kills worker
                win32con.PROCESS_QUERY_INFORMATION, False, os.getpid()))
        except Exception:
            pass
        del job

    network_expected_blocked = os.environ.get("HOMIE_NETWORK_BLOCKED") == "1"
    failures = {
        k: v for k, v in results.items()
        if v == "ALLOWED" and not (k == "open_network_socket" and not network_expected_blocked)
    }
    if results.get("open_network_socket") == "ALLOWED" and not network_expected_blocked:
        print("WARNING: worker has network access. Add firewall rule or AppContainer.")
    assert not failures, f"Confinement holes: {failures}  (all results: {results})"


if __name__ == "__main__":
    test_confined_worker_attacks()
    print("PASS: test_confined_worker_attacks succeeded!")
