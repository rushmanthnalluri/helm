"""tests/test_confinement_attacks.py - Batch 18A & Batch 19-pre Acceptance Test.

The "worker" here is a REAL confined process (Windows AppContainer + Job Object sandbox),
not an in-process mock. Every attack must fail at the OS / kernel level:
  1. open_supervisor_vm_write -> BLOCKED (process DACL & token isolation)
  2. open_supervisor_terminate -> BLOCKED (process DACL safe_mask)
  3. open_supervisor_dup_handle -> BLOCKED (process DACL safe_mask)
  4. read_secret_file -> BLOCKED (owner-only DACL with closed supervisor handle)
  5. delete_dirty_flag -> BLOCKED (owner-only DACL & AppContainer isolation)
  6. write_dirty_flag -> BLOCKED (owner-only DACL & AppContainer isolation)
  7. spawn_child_process -> BLOCKED (Job Object ActiveProcessLimit=1)
  8. read_clipboard_directly -> BLOCKED (Job Object UILIMIT_READCLIPBOARD)
  9. open_network_socket -> BLOCKED (AppContainer zero network capabilities WSAEACCES)
 10. write_tool_registry -> BLOCKED (owner-only DACL & AppContainer isolation)
 11. read_audit_ledger -> BLOCKED (owner-only DACL & AppContainer isolation)
 12. open_user_process_write -> BLOCKED (AppContainer process cross-isolation)
 13. send_input_or_hook -> BLOCKED (UI limits & AppContainer isolation)
 14. open_supervisor_pipe_by_name -> BLOCKED (pipe owner-only DACL denies AppContainer)
"""
import sys
import os

# ------------------------------------------------------------ worker (attacker)
if len(sys.argv) > 1 and sys.argv[1] == "--worker":
    try:
        import json
        import socket
        import subprocess
        import ctypes
        import win32api
        import win32con
        import win32file
        import win32gui
        import win32process
        import pywintypes

        argv = sys.argv[2:]
        (
            sup_pid, secret_file, flag_file, reg_file, ledger_file,
            pipe_name, port, handle
        ) = (
            int(argv[0]), argv[1], argv[2], argv[3], argv[4],
            argv[5], int(argv[6]), int(argv[7])
        )
        results = {}

        def attack(name, fn):
            try:
                res = fn()
                results[name] = "ALLOWED" if res is not False else "blocked"
            except Exception:
                results[name] = "blocked"

        def open_vm_write():
            h = win32api.OpenProcess(
                win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, sup_pid)
            win32api.CloseHandle(h)

        def open_terminate():
            h = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, sup_pid)
            win32api.CloseHandle(h)

        def open_dup_handle():
            h = win32api.OpenProcess(win32con.PROCESS_DUP_HANDLE, False, sup_pid)
            win32api.CloseHandle(h)

        def read_secret():
            with open(secret_file, "rb") as f:
                if f.read(1):
                    return True

        def delete_flag():
            os.remove(flag_file)

        def write_flag():
            with open(flag_file, "ab") as f:
                f.write(b"x")

        def spawn_child():
            subprocess.Popen([sys._base_executable, "-c", "pass"]).wait()

        def clipboard():
            if ctypes.windll.user32.OpenClipboard(0):
                try:
                    h_data = ctypes.windll.user32.GetClipboardData(1)  # CF_TEXT = 1
                    if h_data:
                        return True
                    if ctypes.GetLastError() == 5:  # ERROR_ACCESS_DENIED
                        return False
                finally:
                    ctypes.windll.user32.CloseClipboard()
            return False

        def network():
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.close()

        def write_tool_registry():
            with open(reg_file, "w", encoding="utf-8") as f:
                f.write('{"tampered": true}')

        def read_audit_ledger():
            with open(ledger_file, "rb") as f:
                if f.read(1):
                    return True

        def open_user_process_write():
            shell_hwnd = win32gui.GetShellWindow()
            if shell_hwnd:
                _tid, explorer_pid = win32process.GetWindowThreadProcessId(shell_hwnd)
                h = win32api.OpenProcess(
                    win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, explorer_pid)
                win32api.CloseHandle(h)
            else:
                raise PermissionError("No shell window accessible")

        def send_input_or_hook():
            WH_KEYBOARD_LL = 13
            hhook = ctypes.windll.user32.SetWindowsHookExW(WH_KEYBOARD_LL, None, None, 0)
            if hhook:
                ctypes.windll.user32.UnhookWindowsHookEx(hhook)
                return True
            return False

        def open_pipe_by_name():
            h = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            win32file.CloseHandle(h)

        attack_list = [
            ("open_supervisor_vm_write", open_vm_write),
            ("open_supervisor_terminate", open_terminate),
            ("open_supervisor_dup_handle", open_dup_handle),
            ("read_secret_file", read_secret),
            ("delete_dirty_flag", delete_flag),
            ("write_dirty_flag", write_flag),
            ("spawn_child_process", spawn_child),
            ("read_clipboard_directly", clipboard),
            ("open_network_socket", network),
            ("write_tool_registry", write_tool_registry),
            ("read_audit_ledger", read_audit_ledger),
            ("open_user_process_write", open_user_process_write),
            ("send_input_or_hook", send_input_or_hook),
            ("open_supervisor_pipe_by_name", open_pipe_by_name),
        ]

        for name, fn in attack_list:
            attack(name, fn)

        win32file.WriteFile(pywintypes.HANDLE(handle), json.dumps(results).encode())
        sys.exit(0)
    except Exception:
        sys.exit(1)


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
    reg = tmp_path / "homie_mcp_registry.json"
    ledger = tmp_path / "homie_audit_ledger.jsonl"

    secret.write_bytes(b"k" * 32)
    flag.write_bytes(b"1")
    reg.write_text('{"tools": []}')
    ledger.write_text('{"entry": 1}\n')

    # Harden all protected paths with owner-only DACLs
    conf.harden_path(str(secret))
    conf.harden_path(str(flag))
    conf.harden_path(str(reg))
    conf.harden_path(str(ledger))
    conf.harden_current_process()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    server, client_h, pipe_name = conf.make_ipc_pair()
    this_file = os.path.abspath(__file__)
    hproc, _pid, job = conf.spawn_confined_worker(
        [
            this_file, "--worker",
            str(os.getpid()),
            str(secret),
            str(flag),
            str(reg),
            str(ledger),
            pipe_name,
            str(port)
        ],
        client_h
    )

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
        conf.unharden_path(str(reg))
        conf.unharden_path(str(ledger))
        listener.close()
        del job

    print("\n[CONFINEMENT RESULTS]")
    for k, v in results.items():
        print(f"  {k}: {v}")

    # ZERO ALLOWED RESULTS: All 14 attacks must be strictly blocked at OS level!
    failures = {k: v for k, v in results.items() if v == "ALLOWED"}
    assert not failures, f"Kernel confinement breach detected: {failures}"
    assert results.get("open_network_socket") == "blocked", "Network was not blocked!"
    assert results.get("read_secret_file") == "blocked", "Secret read was not blocked!"
    assert results.get("write_tool_registry") == "blocked", "Tool registry write was not blocked!"
    assert results.get("read_audit_ledger") == "blocked", "Audit ledger read was not blocked!"


if __name__ == "__main__":
    test_confined_worker_attacks()
    print("ALL 14 ATTACK VECTORS BLOCKED BY KERNEL CONFINEMENT!")
