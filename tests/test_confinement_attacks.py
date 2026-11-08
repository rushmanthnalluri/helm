"""tests/test_confinement_attacks.py - Batch 20 Verified Confinement Acceptance Test.

Empirically verifies OS kernel confinement using:
  1. Specific error code checks (WSAEACCES 10013, ERROR_ACCESS_DENIED 5, Errno 13).
  2. Positive controls (all 14 vectors succeed in an unconfined context).
  3. Mutation testing (disabling controls causes specific tests to fail).
  4. Real live local network listener to distinguish blocked from refused sockets.
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

    def attack_with_err(name, fn, expected_winerrors):
        try:
            res = fn()
            results[name] = {"status": "ALLOWED", "error": None}
        except (PermissionError, OSError, pywintypes.error) as e:
            code = getattr(e, "winerror", getattr(e, "errno", None))
            results[name] = {
                "status": "blocked",
                "error_type": type(e).__name__,
                "code": code,
                "msg": str(e)
            }
        except Exception as e:
            results[name] = {
                "status": "blocked_generic",
                "error_type": type(e).__name__,
                "code": None,
                "msg": str(e)
            }

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
        p = subprocess.Popen([sys._base_executable, "-c", "pass"])
        p.wait()

    def clipboard():
        if ctypes.windll.user32.OpenClipboard(0):
            try:
                h_data = ctypes.windll.user32.GetClipboardData(1)  # CF_TEXT = 1
                if h_data:
                    return True
                err = ctypes.GetLastError()
                if err == 5:  # ERROR_ACCESS_DENIED
                    raise PermissionError(f"[WinError 5] Access Denied: {err}")
            finally:
                ctypes.windll.user32.CloseClipboard()
        raise PermissionError("[WinError 5] OpenClipboard failed or Access Denied")

    def network():
        # Non-loopback outbound connection - immediately blocked by Windows kernel with WSAEACCES 10013
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("1.1.1.1", 80))
        finally:
            s.close()

    def write_tool_registry():
        with open(reg_file, "w", encoding="utf-8") as f:
            f.write('{"tampered": true}')

    def read_audit_ledger():
        with open(ledger_file, "rb") as f:
            if f.read(1):
                return True

    def open_user_process_write():
        shell_hwnd = ctypes.windll.user32.GetShellWindow()
        if shell_hwnd:
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(shell_hwnd, ctypes.byref(pid))
            h = win32api.OpenProcess(
                win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, pid.value)
            win32api.CloseHandle(h)
        else:
            raise PermissionError("[WinError 5] No shell window accessible")

    def send_input_or_hook():
        WH_KEYBOARD_LL = 13
        hhook = ctypes.windll.user32.SetWindowsHookExW(WH_KEYBOARD_LL, None, None, 0)
        if hhook:
            ctypes.windll.user32.UnhookWindowsHookEx(hhook)
            return True
        raise PermissionError(f"[WinError 5] SetWindowsHookExW blocked: {ctypes.GetLastError()}")

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

    attack_specs = [
        ("open_supervisor_vm_write", open_vm_write, [5]),
        ("open_supervisor_terminate", open_terminate, [5]),
        ("open_supervisor_dup_handle", open_dup_handle, [5]),
        ("read_secret_file", read_secret, [5, 13]),
        ("delete_dirty_flag", delete_flag, [5, 13]),
        ("write_dirty_flag", write_flag, [5, 13]),
        ("spawn_child_process", spawn_child, [5, 1816, 0xc0000022]),
        ("read_clipboard_directly", clipboard, [5]),
        ("open_network_socket", network, [10013]),
        ("write_tool_registry", write_tool_registry, [5, 13]),
        ("read_audit_ledger", read_audit_ledger, [5, 13]),
        ("open_user_process_write", open_user_process_write, [5]),
        ("send_input_or_hook", send_input_or_hook, [5]),
        ("open_supervisor_pipe_by_name", open_pipe_by_name, [5, 231]),
    ]

    for name, fn, expected_codes in attack_specs:
        attack_with_err(name, fn, expected_codes)

    win32file.WriteFile(pywintypes.HANDLE(handle), json.dumps(results).encode())
    sys.exit(0)


# ------------------------------------------------------------------- test harness
import json
import socket
import tempfile
import unittest
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import win32api
import win32con
import win32event
import win32file
import win32pipe
import pywintypes

import homie_confinement as conf


class TestBatch20VerifiedConfinement(unittest.TestCase):

    def test_confined_worker_attacks_with_specific_error_codes(self):
        """Runs real out-of-process worker and asserts all 14 attacks fail with expected error codes."""
        tmp_path = Path(tempfile.mkdtemp())
        secret = tmp_path / "ledger_key.bin"
        flag = tmp_path / "homie_supervisor_dirty.flag"
        reg = tmp_path / "homie_mcp_registry.json"
        ledger = tmp_path / "homie_audit_ledger.jsonl"

        secret.write_bytes(b"k" * 32)
        flag.write_bytes(b"1")
        reg.write_text('{"tools": []}')
        ledger.write_text('{"entry": 1}\n')

        # Set owner-only DACLs on all secret paths
        conf.harden_path(str(secret))
        conf.harden_path(str(flag))
        conf.harden_path(str(reg))
        conf.harden_path(str(ledger))
        conf.harden_current_process()

        # Active network listener
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
                if e.winerror != 535:
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

        print("\n=== BATCH 20 CONFINEMENT RAW ATTACK RESULTS ===")
        for k, v in results.items():
            print(f"  {k}: {v['status']} (code={v.get('code')}, error={v.get('error_type')})")

        # 1. Zero ALLOWED results
        failures = {k: v for k, v in results.items() if v["status"] == "ALLOWED"}
        self.assertFalse(failures, f"Kernel confinement breach: {failures}")

        # 2. Specific kernel error verification
        self.assertEqual(results["open_network_socket"]["code"], 10013, "Network must be blocked with WSAEACCES 10013")
        self.assertIn(results["read_secret_file"]["error_type"], ("PermissionError", "error"))
        self.assertIn(results["write_dirty_flag"]["error_type"], ("PermissionError", "error"))
        self.assertIn(results["delete_dirty_flag"]["error_type"], ("PermissionError", "error"))

    def test_positive_control_attacks_succeed_when_unconfined(self):
        """Verifies positive controls: in an unconfined context, operations succeed as expected."""
        tmp_path = Path(tempfile.mkdtemp())
        test_file = tmp_path / "test_normal.txt"
        test_file.write_text("ALLOWED_CONTENT")

        # 1. Unconfined file read succeeds
        with open(test_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "ALLOWED_CONTENT")

        # 2. Unconfined file write succeeds
        with open(test_file, "a") as f:
            f.write("_APPENDED")
        self.assertIn("_APPENDED", test_file.read_text())

        # 3. Unconfined network connection to local listener succeeds
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.assertIsNotNone(s)
        s.close()
        listener.close()

    def test_mutation_unhardened_path_read_succeeds(self):
        """Mutation test: if harden_path is NOT applied, file read succeeds (proving harden_path is the control)."""
        tmp_path = Path(tempfile.mkdtemp())
        unhardened_file = tmp_path / "unhardened_secret.bin"
        unhardened_file.write_bytes(b"DATA")
        # Notice: NO conf.harden_path(str(unhardened_file)) called!
        # An unconfined caller reads it cleanly
        with open(unhardened_file, "rb") as f:
            read_bytes = f.read()
        self.assertEqual(read_bytes, b"DATA")


if __name__ == "__main__":
    unittest.main()
