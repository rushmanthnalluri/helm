"""homie_confinement.py - Batch 18A & Batch 19-pre (Windows only).

Provides hardware and kernel-level confinement for untrusted LLM workers:
  * Worker runs inside a Windows AppContainer (LowBox token) with ZERO network capabilities
    (kernel-enforced network denial; socket.connect fails with WSAEACCES WinError 10013).
  * True DACL file isolation: AppContainer token lacks access to any owner-only user files
    (ledger_key, dirty flag, MCP registry) even when the supervisor closes its handles.
  * Job object sandbox: KILL_ON_JOB_CLOSE, ActiveProcessLimit=1 (fork bombing blocked),
    UI limits (clipboard, handles, desktop, global atoms, exit windows, sysparams).
  * IPC via an inherited handle to an unnamed-by-convention random pipe, so the
    worker cannot connect by pipe name.
  * Supervisor process DACL hardening so supervisor cannot be opened with PROCESS_TERMINATE
    or VM manipulation rights.
"""
import ctypes
from ctypes import wintypes
import os
import secrets
import subprocess
import sys

import ntsecuritycon as nsc
import pywintypes
import win32api
import win32con
import win32file
import win32job
import win32pipe
import win32process
import win32security
import win32service

LOW_IL_SID = "S-1-16-4096"
ALL_APP_PACKAGES_SID = "S-1-15-2-1"
APP_CONTAINER_NAME = "HomieWorkerContainer"
PIPE_BUF = 1 << 20

# Win32 / Userenv Ctypes Definitions for AppContainer & AttributeList
kernel32 = ctypes.windll.kernel32
userenv = ctypes.windll.userenv
advapi32 = ctypes.windll.advapi32

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
EXTENDED_STARTUPINFO_PRESENT = 0x00080000

class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]

class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
        ("lpAttributeList", ctypes.c_void_p),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

_CACHED_CONTAINER_SID = None


def _sid(s):
    return win32security.ConvertStringSidToSid(s)


def _my_sid():
    tok = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    return win32security.GetTokenInformation(tok, win32security.TokenUser)[0]


def _owner_only_dacl(access_mask):
    """DACL granting only the current user and SYSTEM, explicitly omitting AppContainer."""
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access_mask, _my_sid())
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access_mask, _sid("S-1-5-18"))
    return dacl


def get_appcontainer_sid():
    """Retrieves or creates the AppContainer SID."""
    global _CACHED_CONTAINER_SID
    if _CACHED_CONTAINER_SID is not None:
        return _CACHED_CONTAINER_SID

    CreateAppContainerProfile = userenv.CreateAppContainerProfile
    CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
    ]
    CreateAppContainerProfile.restype = ctypes.c_long

    sid_ptr = ctypes.c_void_p()
    try:
        hr = CreateAppContainerProfile(
            APP_CONTAINER_NAME,
            "Homie Worker Sandbox",
            "Homie Confined Worker AppContainer",
            None, 0, ctypes.byref(sid_ptr)
        )
    except OSError:
        pass

    DeriveAppContainerSidFromAppContainerName = userenv.DeriveAppContainerSidFromAppContainerName
    DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long

    sid_out = ctypes.c_void_p()
    hr2 = DeriveAppContainerSidFromAppContainerName(APP_CONTAINER_NAME, ctypes.byref(sid_out))
    if hr2 != 0:
        raise ctypes.WinError(hr2)

    _CACHED_CONTAINER_SID = sid_out
    return _CACHED_CONTAINER_SID


def ensure_desktop_low_integrity():
    """Ensure interactive desktop and window station allow sandboxed processes to initialize DLLs."""
    try:
        hdesk = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())
        sd_desk = win32security.GetUserObjectSecurity(
            hdesk, win32security.LABEL_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        sacl = win32security.ACL()
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1
        sacl.AddMandatoryAce(win32security.ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, _sid(LOW_IL_SID))
        sd_desk.SetSecurityDescriptorSacl(1, sacl, 0)

        dacl_desk = sd_desk.GetSecurityDescriptorDacl() or win32security.ACL()
        dacl_desk.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, _sid(ALL_APP_PACKAGES_SID))
        sd_desk.SetSecurityDescriptorDacl(1, dacl_desk, 0)
        win32security.SetUserObjectSecurity(
            hdesk, win32security.LABEL_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION, sd_desk)
    except Exception:
        pass

    try:
        hwinsta = win32service.GetProcessWindowStation()
        sd_winsta = win32security.GetUserObjectSecurity(
            hwinsta, win32security.LABEL_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        sacl_w = win32security.ACL()
        sacl_w.AddMandatoryAce(win32security.ACL_REVISION, 0, 0x1, _sid(LOW_IL_SID))
        sd_winsta.SetSecurityDescriptorSacl(1, sacl_w, 0)

        dacl_winsta = sd_winsta.GetSecurityDescriptorDacl() or win32security.ACL()
        dacl_winsta.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, _sid(ALL_APP_PACKAGES_SID))
        sd_winsta.SetSecurityDescriptorDacl(1, dacl_winsta, 0)
        win32security.SetUserObjectSecurity(
            hwinsta, win32security.LABEL_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION, sd_winsta)
    except Exception:
        pass


# ---------------------------------------------------------------- DACL helpers
def harden_path(path):
    """Make a file/dir owner-only with protected DACL.
    AppContainer processes (and Low-IL tokens) are denied read, write, and delete at the OS level
    even when NO supervisor handle is open."""
    norm_path = os.path.abspath(path)
    dacl = _owner_only_dacl(nsc.FILE_ALL_ACCESS)
    win32security.SetNamedSecurityInfo(
        norm_path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


def unharden_path(path):
    """Helper to unharden or clean up."""
    pass


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

    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32file.GENERIC_READ | win32file.GENERIC_WRITE, _my_sid())
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32file.GENERIC_READ | win32file.GENERIC_WRITE, _sid("S-1-5-18"))
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32file.GENERIC_READ | win32file.GENERIC_WRITE, _sid(ALL_APP_PACKAGES_SID))

    sd = pywintypes.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
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
    env["PYTHONNOUSERSITE"] = "1"
    return env


def spawn_confined_worker(args, client_handle_int):
    """args: list of args AFTER the interpreter, e.g. ['-m', 'homie_worker'].
    Spawns worker in a zero-network-capability AppContainer + Job Object.
    Returns (process_handle, pid, job). Keep `job` referenced for the worker's
    lifetime: closing it kills the worker (KILL_ON_JOB_CLOSE)."""
    ensure_desktop_low_integrity()
    sid_appcontainer = get_appcontainer_sid()
    job = build_job()

    argv = [sys._base_executable] + list(args) + [str(client_handle_int)]
    cmdline = subprocess.list2cmdline(argv)

    # Security capabilities structure (Zero network capabilities)
    sec_cap = SECURITY_CAPABILITIES()
    sec_cap.AppContainerSid = sid_appcontainer
    sec_cap.Capabilities = None
    sec_cap.CapabilityCount = 0
    sec_cap.Reserved = 0

    # Initialize PROC_THREAD_ATTRIBUTE_LIST
    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attr_buf = ctypes.create_string_buffer(size.value)
    lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)
    if not kernel32.InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError()

    if not kernel32.UpdateProcThreadAttribute(
        lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(sec_cap),
        ctypes.sizeof(sec_cap),
        None,
        None
    ):
        raise ctypes.WinError()

    siex = STARTUPINFOEXW()
    siex.cb = ctypes.sizeof(STARTUPINFOEXW)
    siex.lpAttributeList = lpAttributeList

    # siex.dwFlags |= win32process.STARTF_USESTDHANDLES

    pi = PROCESS_INFORMATION()

    # Pass client_handle_int as inheritable handle
    flags = EXTENDED_STARTUPINFO_PRESENT | win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW

    ok = kernel32.CreateProcessW(
        None,
        cmdline,
        None,
        None,
        True,  # bInheritHandles = True so client_handle_int is accessible
        flags,
        None,
        None,
        ctypes.byref(siex),
        ctypes.byref(pi)
    )

    kernel32.DeleteProcThreadAttributeList(lpAttributeList)

    if not ok:
        raise ctypes.WinError()

    hproc = pywintypes.HANDLE(pi.hProcess)
    hthread = pywintypes.HANDLE(pi.hThread)

    try:
        win32job.AssignProcessToJobObject(job, hproc)
    except Exception:
        win32process.TerminateProcess(hproc, 1)
        win32api.CloseHandle(hthread)
        raise

    win32process.ResumeThread(hthread)
    win32api.CloseHandle(hthread)
    try:
        win32api.CloseHandle(client_handle_int)
    except Exception:
        pass
    return hproc, pi.dwProcessId, job
