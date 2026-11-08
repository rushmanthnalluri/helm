"""homie_confinement.py - Batch 18A (Windows only, requires pywin32).

Provides hardware and kernel-level confinement for untrusted LLM workers:
  * Worker runs with a restricted token: privileges stripped (DISABLE_MAX_PRIVILEGE),
    Administrators deny-only.
  * Low integrity level (UIPI blocks input injection into higher-IL windows and protects
    supervisor memory/handles).
  * Job object: KILL_ON_JOB_CLOSE, ActiveProcessLimit=1 (fork bombing blocked), UI limits
    (clipboard, handles, desktop, global atoms, exit windows, sysparams).
  * IPC via an inherited handle to an unnamed-by-convention random pipe, so the
    worker has no pipe name worth connecting to.
  * Process DACL hardening so the supervisor process cannot be opened with PROCESS_TERMINATE
    or VM manipulation rights.
  * File-level isolation via non-inheriting owner-only DACLs and exclusive lease locks so
    confidential keys (ledger_key.bin, dirty flag) cannot be read, written, or deleted by worker.
"""
import ctypes
import os
import secrets
import subprocess
import sys

import ntsecuritycon as nsc
import pywintypes
import win32api
import win32con
import win32file
import win32gui
import win32job
import win32pipe
import win32process
import win32security
import win32service

LOW_IL_SID = "S-1-16-4096"
SE_GROUP_INTEGRITY = 0x00000020
ADMIN_SIDS_TO_DISABLE = ["S-1-5-32-544"]  # BUILTIN\Administrators
PIPE_BUF = 1 << 20

# Active exclusive locks for hardened paths held by supervisor
_HARDENED_FILE_HANDLES = {}


def _sid(s):
    return win32security.ConvertStringSidToSid(s)


def _my_sid():
    tok = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    return win32security.GetTokenInformation(tok, win32security.TokenUser)[0]


def _owner_only_dacl(access_mask):
    """DACL granting only the current user and SYSTEM."""
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access_mask, _my_sid())
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access_mask, _sid("S-1-5-18"))
    return dacl


def ensure_desktop_low_integrity():
    """Ensure the interactive desktop and window station allow Low-IL processes to initialize DLLs."""
    try:
        hdesk = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())
        sd_desk = win32security.GetUserObjectSecurity(hdesk, win32security.LABEL_SECURITY_INFORMATION)
        sacl = win32security.ACL()
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1
        sacl.AddMandatoryAce(win32security.ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, _sid(LOW_IL_SID))
        sd_desk.SetSecurityDescriptorSacl(1, sacl, 0)
        win32security.SetUserObjectSecurity(hdesk, win32security.LABEL_SECURITY_INFORMATION, sd_desk)
    except Exception:
        pass

    try:
        hwinsta = win32service.GetProcessWindowStation()
        sd_winsta = win32security.GetUserObjectSecurity(hwinsta, win32security.LABEL_SECURITY_INFORMATION)
        sacl_w = win32security.ACL()
        sacl_w.AddMandatoryAce(win32security.ACL_REVISION, 0, 0x1, _sid(LOW_IL_SID))
        sd_winsta.SetSecurityDescriptorSacl(1, sacl_w, 0)
        win32security.SetUserObjectSecurity(hwinsta, win32security.LABEL_SECURITY_INFORMATION, sd_winsta)
    except Exception:
        pass


# ---------------------------------------------------------------- DACL helpers
def harden_path(path):
    """Make a file/dir owner-only and hold an exclusive handle (FILE_SHARE=0).
    The confined worker token is denied read, write, and delete at the OS level."""
    norm_path = os.path.abspath(path)
    dacl = _owner_only_dacl(nsc.FILE_ALL_ACCESS)
    win32security.SetNamedSecurityInfo(
        norm_path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)

    # If already held, close existing
    if norm_path in _HARDENED_FILE_HANDLES:
        try:
            _HARDENED_FILE_HANDLES[norm_path].Close()
        except Exception:
            pass

    # Acquire exclusive non-shared handle
    try:
        hfile = win32file.CreateFile(
            norm_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,  # FILE_SHARE=0 (exclusive lock)
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        _HARDENED_FILE_HANDLES[norm_path] = hfile
    except Exception:
        pass


def unharden_path(path):
    """Release exclusive handle for a path."""
    norm_path = os.path.abspath(path)
    if norm_path in _HARDENED_FILE_HANDLES:
        try:
            _HARDENED_FILE_HANDLES[norm_path].Close()
        except Exception:
            pass
        del _HARDENED_FILE_HANDLES[norm_path]


def harden_current_process():
    """Deny PROCESS_TERMINATE, PROCESS_VM_*, DUP_HANDLE etc. to callers
    so the supervisor cannot be terminated or injected by any untrusted worker."""
    safe_mask = (win32con.PROCESS_ALL_ACCESS
                 & ~win32con.PROCESS_TERMINATE
                 & ~win32con.PROCESS_VM_WRITE
                 & ~win32con.PROCESS_VM_OPERATION
                 & ~win32con.PROCESS_DUP_HANDLE)
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, safe_mask, _my_sid())
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.PROCESS_ALL_ACCESS, _sid("S-1-5-18"))
    win32security.SetSecurityInfo(
        win32api.GetCurrentProcess(), win32security.SE_KERNEL_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


# ---------------------------------------------------------------------- token
def build_worker_token():
    proc_tok = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_ALL_ACCESS)
    restricted = win32security.CreateRestrictedToken(
        proc_tok,
        win32security.DISABLE_MAX_PRIVILEGE,
        [(_sid(s), 0) for s in ADMIN_SIDS_TO_DISABLE],
        None,
        None,
    )
    win32security.SetTokenInformation(
        restricted, win32security.TokenIntegrityLevel,
        (_sid(LOW_IL_SID), SE_GROUP_INTEGRITY))
    return restricted


# ------------------------------------------------------------------------ job
def build_job():
    job = win32job.CreateJobObject(None, "")
    info = win32job.QueryInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation)
    basic = info["BasicLimitInformation"]
    basic["LimitFlags"] |= (
        win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    basic["ActiveProcessLimit"] = 1
    win32job.SetInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation, info)

    ui = (win32job.JOB_OBJECT_UILIMIT_HANDLES
          | win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD
          | win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD
          | win32job.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
          | win32job.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
          | win32job.JOB_OBJECT_UILIMIT_GLOBALATOMS
          | win32job.JOB_OBJECT_UILIMIT_DESKTOP
          | win32job.JOB_OBJECT_UILIMIT_EXITWINDOWS)
    win32job.SetInformationJobObject(
        job, win32job.JobObjectBasicUIRestrictions, {"UIRestrictionsClass": ui})
    return job


# ------------------------------------------------------------------------ IPC
def make_ipc_pair():
    """Supervisor creates the pipe, opens the client end itself with an
    inheritable handle, and passes only the numeric handle to the worker.
    Returns (server_handle, client_handle_int, name)."""
    name = r"\\.\pipe\homie-" + secrets.token_hex(16)

    sd = pywintypes.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, _owner_only_dacl(
        win32file.GENERIC_READ | win32file.GENERIC_WRITE), 0)
    server_sa = pywintypes.SECURITY_ATTRIBUTES()
    server_sa.SECURITY_DESCRIPTOR = sd
    server_sa.bInheritHandle = False

    server = win32pipe.CreateNamedPipe(
        name,
        win32pipe.PIPE_ACCESS_DUPLEX | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE
        | win32pipe.PIPE_WAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1, PIPE_BUF, PIPE_BUF, 0, server_sa)

    client_sa = pywintypes.SECURITY_ATTRIBUTES()
    client_sa.bInheritHandle = True
    client = win32file.CreateFile(
        name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0,
        client_sa, win32file.OPEN_EXISTING, 0, None)
    
    # Detach to preserve the underlying Windows handle across Python garbage collection
    client_handle_int = client.Detach()
    return server, client_handle_int, name


# ---------------------------------------------------------------------- spawn
def _minimal_env():
    keep = (
        "SystemRoot", "SystemDrive", "TEMP", "TMP", "PATH",
        "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData",
    )
    env = {k: os.environ[k] for k in keep if k in os.environ}
    # Point temporary folders to Low IL temp if available
    low_temp = os.path.expanduser(r"~\AppData\Local\Temp\Low")
    if os.path.exists(low_temp):
        env["TEMP"] = low_temp
        env["TMP"] = low_temp
    env["PYTHONNOUSERSITE"] = "1"
    return env  # no API keys, no tokens, no supervisor secrets


def spawn_confined_worker(args, client_handle_int):
    """args: list of args AFTER the interpreter, e.g. ['-m', 'homie_worker'].
    Returns (process_handle, pid, job). Keep `job` referenced for the worker's
    lifetime: closing it kills the worker (KILL_ON_JOB_CLOSE)."""
    ensure_desktop_low_integrity()
    token = build_worker_token()
    job = build_job()

    argv = [sys._base_executable] + list(args) + [str(client_handle_int)]
    cmdline = subprocess.list2cmdline(argv)

    si = win32process.STARTUPINFO()
    # Explicitly redirect standard handles to NUL so pytest capture pipes are not leaked
    try:
        sa_nul = pywintypes.SECURITY_ATTRIBUTES()
        sa_nul.bInheritHandle = True
        h_nul = win32file.CreateFile(
            "NUL", win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            sa_nul, win32file.OPEN_EXISTING, 0, None
        )
        si.dwFlags |= win32process.STARTF_USESTDHANDLES
        si.hStdInput = h_nul
        si.hStdOutput = h_nul
        si.hStdError = h_nul
    except Exception:
        pass

    hproc, hthread, pid, _tid = win32process.CreateProcessAsUser(
        token, None, cmdline, None, None, True,
        win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW,
        _minimal_env(), None, si)

    try:
        win32job.AssignProcessToJobObject(job, hproc)
    except Exception:
        win32process.TerminateProcess(hproc, 1)  # never run unjobbed
        raise
    win32process.ResumeThread(hthread)
    return hproc, pid, job
