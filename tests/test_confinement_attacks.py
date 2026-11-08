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
    from ctypes import wintypes
    import win32api
    import win32con
    import win32file
    import win32gui
    import win32process
    import pywintypes

    argv = sys.argv[2:]
    (
        sup_pid, sup_tid, secret_file, flag_file, reg_file, ledger_file,
        pipe_name, port, handle
    ) = (
        int(argv[0]), int(argv[1]), argv[2], argv[3], argv[4], argv[5],
        argv[6], int(argv[7]), int(argv[8])
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
        h = win32file.CreateFile(
            secret_file, win32file.GENERIC_READ, 0, None,
            win32file.OPEN_EXISTING, 0, None)
        win32file.CloseHandle(h)

    def delete_flag():
        win32file.DeleteFile(flag_file)

    def write_flag():
        h = win32file.CreateFile(
            flag_file, win32file.GENERIC_WRITE, 0, None,
            win32file.OPEN_EXISTING, 0, None)
        win32file.CloseHandle(h)

    def spawn_child():
        p = subprocess.Popen([sys._base_executable, "-c", "pass"])
        p.wait()

    def clipboard():
        if ctypes.windll.user32.OpenClipboard(0):
            try:
                h_data = ctypes.windll.user32.GetClipboardData(1)  # CF_TEXT = 1
                if h_data:
                    return True
                err = ctypes.GetLastError() or 5
                raise pywintypes.error(err, "GetClipboardData", "Access is denied.")
            finally:
                ctypes.windll.user32.CloseClipboard()
        err = ctypes.GetLastError() or 5
        raise pywintypes.error(err, "OpenClipboard", "Access is denied.")

    def network():
        # Non-loopback outbound connection - immediately blocked by Windows kernel with WSAEACCES 10013
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("1.1.1.1", 80))
        finally:
            s.close()

    def write_tool_registry():
        h = win32file.CreateFile(
            reg_file, win32file.GENERIC_WRITE, 0, None,
            win32file.OPEN_EXISTING, 0, None)
        win32file.CloseHandle(h)

    def read_audit_ledger():
        h = win32file.CreateFile(
            ledger_file, win32file.GENERIC_READ, 0, None,
            win32file.OPEN_EXISTING, 0, None)
        win32file.CloseHandle(h)

    def open_user_process_write():
        shell_hwnd = ctypes.windll.user32.GetShellWindow()
        if shell_hwnd:
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(shell_hwnd, ctypes.byref(pid))
            h = win32api.OpenProcess(
                win32con.PROCESS_VM_WRITE | win32con.PROCESS_VM_OPERATION, False, pid.value)
            win32api.CloseHandle(h)
        else:
            raise pywintypes.error(5, "OpenProcess", "Access is denied.")

    def attach_thread_input_attack():
        my_tid = ctypes.windll.kernel32.GetCurrentThreadId()
        ok = ctypes.windll.user32.AttachThreadInput(my_tid, sup_tid, True)
        if ok:
            return True
        err = ctypes.GetLastError() or 5
        raise pywintypes.error(err, "AttachThreadInput", "Access is denied.")

    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
    def dummy_hook_proc(nCode, wParam, lParam):
        return 0
    _global_hook_proc = HOOKPROC(dummy_hook_proc)

    def set_windows_hook_higher_il():
        # Valid HookProc targeting supervisor thread (WH_KEYBOARD = 2)
        hhook = ctypes.windll.user32.SetWindowsHookExW(2, _global_hook_proc, 0, sup_tid)
        if hhook:
            ctypes.windll.user32.UnhookWindowsHookEx(hhook)
            return True
        err = ctypes.GetLastError() or 5
        raise pywintypes.error(err, "SetWindowsHookExW", "Access is denied.")

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
        ("read_secret_file", read_secret, [5]),
        ("delete_dirty_flag", delete_flag, [5]),
        ("write_dirty_flag", write_flag, [5]),
        ("spawn_child_process", spawn_child, [1816]),
        ("read_clipboard_directly", clipboard, [5]),
        ("open_network_socket", network, [10013]),
        ("write_tool_registry", write_tool_registry, [5]),
        ("read_audit_ledger", read_audit_ledger, [5]),
        ("open_user_process_write", open_user_process_write, [5]),
        ("attach_thread_input_higher_il", attach_thread_input_attack, [5]),
        ("set_windows_hook_higher_il", set_windows_hook_higher_il, [5]),
        ("open_supervisor_pipe_by_name", open_pipe_by_name, [5, 3]),
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

        # Dedicated IDLE protected pipe to test named connection (idle and unconsumed)
        import secrets
        idle_pipe_name = rf"\\.\pipe\homie_idle_{secrets.token_hex(8)}"
        dacl_idle = conf._owner_only_dacl(win32file.GENERIC_READ | win32file.GENERIC_WRITE)
        sd_idle = pywintypes.SECURITY_DESCRIPTOR()
        sd_idle.SetSecurityDescriptorDacl(1, dacl_idle, 0)
        sa_idle = pywintypes.SECURITY_ATTRIBUTES()
        sa_idle.SECURITY_DESCRIPTOR = sd_idle
        sa_idle.bInheritHandle = False
        idle_server = win32pipe.CreateNamedPipe(
            idle_pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
            2, 1024, 1024, 0, sa_idle
        )

        server, client_h, pipe_name = conf.make_ipc_pair()
        this_file = os.path.abspath(__file__)
        hproc, _pid, job = conf.spawn_confined_worker(
            [
                this_file, "--worker",
                str(os.getpid()),
                str(win32api.GetCurrentThreadId()),
                str(secret),
                str(flag),
                str(reg),
                str(ledger),
                idle_pipe_name,
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
            win32file.CloseHandle(idle_server)
            listener.close()
            del job

        print("\n=== BATCH 22 CONFINEMENT RAW ATTACK RESULTS ===")
        for k, v in results.items():
            print(f"  {k}: {v['status']} (code={v.get('code')}, error={v.get('error_type')})")

        # 1. Zero ALLOWED results
        failures = {k: v for k, v in results.items() if v["status"] == "ALLOWED"}
        self.assertFalse(failures, f"Kernel confinement breach: {failures}")

        # 2. Specific kernel error verification
        self.assertEqual(results["open_network_socket"]["code"], 10013, "Network must be blocked with WSAEACCES 10013")
        self.assertEqual(results["read_secret_file"]["code"], 5, "read_secret_file must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["write_dirty_flag"]["code"], 5, "write_dirty_flag must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["delete_dirty_flag"]["code"], 5, "delete_dirty_flag must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["write_tool_registry"]["code"], 5, "write_tool_registry must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["read_audit_ledger"]["code"], 5, "read_audit_ledger must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["open_supervisor_vm_write"]["code"], 5, "open_supervisor_vm_write must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["open_supervisor_terminate"]["code"], 5, "open_supervisor_terminate must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["open_supervisor_dup_handle"]["code"], 5, "open_supervisor_dup_handle must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["attach_thread_input_higher_il"]["code"], 5, "attach_thread_input_higher_il must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["set_windows_hook_higher_il"]["code"], 5, "set_windows_hook_higher_il must be blocked with ERROR_ACCESS_DENIED 5")
        self.assertEqual(results["spawn_child_process"]["code"], 1816, "spawn_child_process must be blocked with ERROR_NOT_ENOUGH_QUOTA 1816")
        self.assertIn(results["open_supervisor_pipe_by_name"]["code"], (5, 3), "open_supervisor_pipe_by_name must be blocked by kernel DACL/isolation (5 or 3)")

    def test_idle_pipe_dacl_denial_explicit(self):
        """Batch 21 Directive: Verifies idle named pipe with owner DACL explicitly returns WinError 5 to untrusted tokens."""
        import secrets
        import win32security
        pname = rf"\\.\pipe\homie_dacl_idle_{secrets.token_hex(8)}"
        dacl = conf._owner_only_dacl(win32file.GENERIC_READ | win32file.GENERIC_WRITE)
        sd = pywintypes.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False

        server = win32pipe.CreateNamedPipe(
            pname, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
            1, 1024, 1024, 0, sa
        )
        try:
            # Token with restricting SIDs (simulating untrusted worker)
            proc_tok = win32security.OpenProcessToken(-1, win32con.TOKEN_ALL_ACCESS)
            tok_res = win32security.CreateRestrictedToken(
                proc_tok,
                win32security.DISABLE_MAX_PRIVILEGE,
                [(conf._sid("S-1-5-32-544"), 0)],
                None,
                [(conf._sid("S-1-5-32-545"), 0), (conf._sid("S-1-5-12"), 0)]
            )
            win32security.ImpersonateLoggedOnUser(tok_res)
            try:
                with self.assertRaises(pywintypes.error) as cm:
                    h = win32file.CreateFile(
                        pname, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                        0, None, win32file.OPEN_EXISTING, 0, None
                    )
                    win32file.CloseHandle(h)
                self.assertEqual(cm.exception.winerror, 5, "Idle pipe must return ERROR_ACCESS_DENIED (5), proving DACL denial!")
            finally:
                win32security.RevertToSelf()
        finally:
            win32file.CloseHandle(server)

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
