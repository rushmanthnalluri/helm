# Homie AI Workstation Assistant: Formal Security Threat Model

## 1. System Architecture & Trust Boundaries

The Homie architecture partitions execution into strictly separated trust zones:
```
+-------------------------------------------------------------------------+
|                              USER WORKSTATION                           |
|                                                                         |
|  +--------------------+         HMAC Heartbeat     +-----------------+  |
|  | Policy Supervisor  |<==========================>| Watchdog Process|  |
|  | (High-Integrity    |                            | (Independent,   |  |
|  |  Standard User)    |---+                        |  Hardened DACL, |  |
|  +--------------------+   | Duplicated Job Handle  |  Physical Hook) |  |
|            |              +----------------------->+-----------------+  |
|            | IPC Pipe (Inherited Handle Only)               |           |
|            v                                                |           |
|  +--------------------+                                     |           |
|  |  Confined Worker   |                                     |           |
|  | (AppContainer,     |<------------------------------------+           |
|  |  Zero Network,     |   win32job.TerminateJobObject                   |
|  |  No Write-Up,      |                                                 |
|  |  ActiveProcess=1)  |                                                 |
|  +--------------------+                                                 |
+-------------------------------------------------------------------------+
             ^
             | Signed WebAuthn Challenge (HTTPS / Out-of-Band)
             v
+-------------------------------------------------------------------------+
|                           MOBILE PHONE GATEWAY                          |
|  Hardware Authenticator (Secure Enclave / Platform Keystore)            |
|  Private Key isolated from PC; Single-Use Monotonic Sequence Counter    |
+-------------------------------------------------------------------------+
```

---

## 2. Kernel & OS-Level Security Guarantees

Homie provides empirically verified, kernel-enforced guarantees on Windows 10/11:

### A. Network Isolation (AppContainer Zero-Capability LowBox Token)
- **Mechanism**: Spawns worker with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and 0 granted network capabilities.
- **Guarantee**: Outbound network requests (`socket.connect`, `socket.create_connection`) are intercepted and blocked by the Windows kernel TCP/IP stack (`PermissionError: [WinError 10013] WSAEACCES`). Untrusted workers cannot open outbound exfiltration sockets or bypass canary monitoring.

### B. Secret & State Storage Protection (Owner-Only DACLs)
- **Mechanism**: Critical assets (`ledger_key.bin`, `homie_supervisor_dirty.flag`, `homie_mcp_registry.json`, `homie_audit_ledger.jsonl`) are hardened with owner-only DACLs (`_my_sid()`, `SYSTEM`) and `PROTECTED_DACL_SECURITY_INFORMATION`.
- **Guarantee**: Even when the supervisor closes its file handles, the worker token is strictly denied `GENERIC_READ`, `GENERIC_WRITE`, and `DELETE` by the NT kernel (`PermissionError: [Errno 13]`).

### C. Sub-process Fork Bombing & UI Injection Defense (Job Object Sandbox)
- **Mechanism**: Windows Job Object with:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (`ActiveProcessLimit = 1`)
  - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
  - UI Limits: `UILIMIT_READCLIPBOARD`, `UILIMIT_WRITECLIPBOARD`, `UILIMIT_HANDLES`, `UILIMIT_DESKTOP`.
- **Guarantee**: Worker cannot spawn sub-processes (`OSError: [WinError 1816]`), cannot read/write system clipboard directly, and cannot open window station handles. Terminating or crashing the supervisor immediately terminates all worker processes.

### D. Hardware Kill Hotkey & Synthetic Keystroke Rejection (Independent Watchdog)
- **Mechanism**: `WH_KEYBOARD_LL` low-level keyboard hook running on a dedicated thread with its own message loop.
- **Guarantee**: Keystrokes with `LLKHF_INJECTED` (0x01) or `LLKHF_LOWER_IL_INJECTED` (0x02) are rejected. Malicious scripts or SendInput cannot trigger or disarm the emergency switch. True kill latency to process death is measured at **< 3ms**.

### E. Screen Capture & Screen-Memory Exclusion (Hardware HUD & Pairing)
- **Mechanism**: Transparent overlay and enrollment pairing windows set `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
- **Guarantee**: OS screen capture APIs (DWM, Snipping Tool, OBS, agent screenshots) render transparent black, preventing screen memory OCR ingestion from leaking one-time enrollment codes or contaminating vision models.

---

## 3. Policy & Mediation Guarantees

### A. Complete Mediation of Actuator Effects
- Any side-effect tool execution (`WRITE_EXEC`, `ELEVATED_CONFIRM`) attempted without a validated two-phase supervisor `INTENT` token fails closed immediately (`DENY_COMPLETE_MEDIATION_BREACH`).

### B. Dynamic Policy Envelopes
- Human approval fatigue is mitigated by mobile-signed bounded envelopes (allowed process images, allowed actions, step budget, keystroke cap, TTL, taint epoch).
- Out-of-envelope actions are **hard-denied** (never prompted).
- High-risk operations (Send, Delete, Pay, Submit, Install) ALWAYS require per-step step-up approval even inside active envelopes.

---

## 4. Explicit Non-Guarantees & Out-of-Scope Risks

The following attack vectors are outside Homie's threat model and cannot be mitigated at the application layer:

1. **Kernel Compromise (Ring 0 / Rootkits)**: If malicious code executes at the kernel level, all Windows OS access checks, tokens, and DACLs are bypassable.
2. **Pre-Existing Host Malware Running as Same User**: If unsandboxed malware is already running with standard user rights outside Homie prior to launch, it can manipulate unhardened user files.
3. **Physical Console Access / Hardware Keyloggers**: A physical hardware device attached between keyboard and motherboard (or physical access to an unlocked workstation) bypasses software controls.
4. **Compromised Mobile Phone / Hardware Authenticator**: If the user's paired mobile device is jailbroken, infected with malware, or its Secure Enclave private key is compromised, forged approvals can be generated.
5. **Upstream LLM Provider Compromise**: A compromised foundation model provider can return malicious instructions; however, OS kernel confinement and complete mediation prevent those instructions from escaping the sandbox.
