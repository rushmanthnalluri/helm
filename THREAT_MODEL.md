# Helm Desktop Assistant: Security Boundaries and Threat Model

## 1. System Architecture & Trust Boundaries

The design partitions execution into trust zones. The diagram and mechanisms below describe intended boundaries, not independent security certification:
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
|            | IPC Pipe (Inherited Handle Only, No AppContainer Access)|  |
|            v                                                |           |
|  +--------------------+                                     |           |
|  |  Confined Worker   |                                     |           |
|  | (AppContainer,     |<------------------------------------+           |
|  |  Zero Network,     |   win32job.TerminateJobObject                   |
|  |  No Write-Up,      |   Job Object termination path                 |
|  |  ActiveProcess=1)  |                                                 |
|  +--------------------+                                                 |
+-------------------------------------------------------------------------+
             ^
             | Optional local verification (Windows Hello, on selected routes)
             v
+-------------------------------------------------------------------------+
|            WINDOWS HELLO (PLATFORM-MANAGED USER VERIFICATION)            |
|  Available verification methods depend on Windows and device settings   |
+-------------------------------------------------------------------------+
```

---

## 2. Kernel & OS-Level Mechanisms

This document summarizes mechanisms present in the source and the assumptions they rely on. It is not an independent security audit or a guarantee that every app flow or release has been exercised on physical Windows systems. Windows version, device configuration, process launch path, and permissions affect enforcement. Numeric claims require a named test run and environment; no general kill-latency figure is asserted here.

### A. Network Isolation (AppContainer Zero-Capability LowBox Token)
- **Mechanism**: Spawns worker with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and 0 granted network capabilities.
- **Expected effect when configured**: The AppContainer worker is intended to have no network capabilities. Windows enforcement depends on the worker being launched with the configured token and capabilities; this statement does not cover the desktop process or every integration.

### B. Secret & State Storage Protection (Owner-Only Protected DACLs)
- **Mechanism**: Critical assets (`.helm_vault.key`, `ledger_key.bin`, `helm_supervisor_dirty.flag`, `helm_mcp_registry.json`, `helm_audit_ledger.jsonl`) are hardened with owner-only DACLs (`_my_sid()`, `SYSTEM`) and `PROTECTED_DACL_SECURITY_INFORMATION`.
- **Expected effect when configured**: Owner-only DACLs are intended to deny the confined worker read, write, and delete access to protected files. This does not protect secrets from all processes running as the same Windows user.
- **Idle Pipe DACL Protection**: Supervisor named pipes created with `_owner_only_dacl` deny unauthenticated connection attempts with `ERROR_ACCESS_DENIED (5)` even when the pipe instance is idle and unconsumed.

### C. Sub-process Fork Bombing & UI Injection Defense (Job Object Sandbox)
- **Mechanism**: Windows Job Object with:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (`ActiveProcessLimit = 1`)
  - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
  - UI Limits: `UILIMIT_READCLIPBOARD`, `UILIMIT_WRITECLIPBOARD`, `UILIMIT_HANDLES`, `UILIMIT_DESKTOP`.
- **Expected effect when configured**: Job Object limits are intended to restrict child processes and selected UI access, and to terminate job members when the job handle closes. Enforcement depends on successful job assignment and on the worker remaining in that job.

### D. Emergency Kill Hotkey & Injected-Keystroke Filtering (Watchdog)
- **Mechanism**: `WH_KEYBOARD_LL` low-level keyboard hook running on a dedicated thread with its own Win32 message loop (`GetMessageW` / `DispatchMessageW`).
- **Expected effect when configured**: The hook rejects events carrying `LLKHF_INJECTED` or `LLKHF_LOWER_IL_INJECTED`. This does not cover physical HID devices that emit ordinary scan codes. No general kill-latency number is claimed.

### E. Screen Capture & Screen-Memory Exclusion (HUD & Pairing)
- **Mechanism**: Transparent HUD overlay and enrollment pairing windows set `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
- **Expected effect when configured**: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` requests exclusion from supported Windows capture paths. It does not prevent every external camera, capture method, remote session, or compromised process from observing the display.

---

## 3. Cryptographic & Mediation Mechanisms

### A. Supervisor-Side Complete Mediation Invariant
- Any physical actuator effect (`WRITE_EXEC`, `ELEVATED_CONFIRM`) attempted without a validated two-phase supervisor `INTENT` token fails closed immediately (`DENY_COMPLETE_MEDIATION_BREACH`).
- INTENT tokens are cryptographically minted in supervisor private memory using HKDF-SHA256 actuator subkeys (`INTENT_V1:{epoch}:{seq}:{timestamp}:{tool}:{caller_id}:{sig}`). Worker processes cannot mint or forge tokens.

### B. Dynamic Policy Envelopes & Domain Scoping
- Bounded execution envelopes restrict target application images, action types, step budget, keystroke cap, TTL, and taint epoch.
- **Prohibited Images**: Arbitrary execution environments (Explorer, Cmd, PowerShell, WT, Code, Word, Excel) cannot be approved in envelopes.
- **Browser Domain Scoping**: Browsers in an envelope are strictly bound to an explicit domain allowlist (`allowed_domains`). Out-of-scope domain navigations are hard-denied.
- **Semantic Control Gating**: Disguised submission controls ("Continue", "Next", "Agree", Enter-to-submit form patterns) require per-step step-up human approval.

### C. Vault Subkey Separation & Key Derivation
- Master vault keys require minimum 32 bytes (256 bits).
- Format version byte (`0x01`) encapsulates all encrypted at-rest tokens (`vault:`).
- HKDF-SHA256 derives domain-separated cryptographic subkeys for `storage`, `audit`, `session`, and `actuator`, preventing cross-domain token transplantation.

### D. Workstation Process Boundaries & Out-of-Process Supervisor Split (Batch 41 Deployed)
- **Same-User Host Environment Realities**: On a standard single-user Windows workstation operating without a dedicated privileged Windows Service running as `NT AUTHORITY\SYSTEM`, all processes running under the same interactive standard user account share the same filesystem access rights. Unsandboxed, pre-existing same-user host malware can arbitrarily inspect or modify files owned by that user.
- **Out-of-Process Supervisor Daemon & Pipe Client Split**: In Batch 41, the Policy Supervisor was decoupled into a dedicated out-of-process daemon (`helm_supervisor_daemon.py`) communicating over Windows Named Pipe `\\.\pipe\helm_supervisor` with kernel-attested client validation (`GetNamedPipeClientProcessId`). The daemon holds exclusive custody of the cryptographic INTENT V2 HMAC signing keys, HMAC-SHA256 audit ledger, and physical actuators. The UI/broker process (`action_broker.py`) operates as a pipe client holding no signing keys, and fails closed immediately across all channels if the supervisor process is unreachable or terminated.
- **Route-specific action approval**: `ActionBroker` selects `WindowsHelloGate` for medium- and high-risk actions. That gate fails closed when Windows Hello is unavailable unless an explicit fallback approver is configured. Separately, supervisor-protected consequential actions require cryptographically signed evidence from an enrolled device; the supervisor denies those actions when no device is enrolled. A Windows Hello result in the broker does not replace the supervisor's enrolled-device signature. These are distinct checks, not a universal Windows Hello approval path.
- **Hardware Grounding & Anti-DoS ACLs**: Recovery token file DACL explicitly denies `DELETE` permission to standard `Users` SID (`S-1-5-32-545`), preventing unprivileged denial-of-service deletion. Script self-elevation via `ShellExecuteW(runas)` has been removed, eliminating user-space hijacking of user-writable scripts.
- **Evidence-Based Security (Store Evidence, Not a Verdict)**: To ensure integrity against untrusted local worker injection or malicious database writes, the Policy Supervisor never treats row presence or unsigned SQLite boolean flags as an authorization verdict. Every approval requires an explicit, tamper-evident challenge token.
- **Persistent Nonce Single-Use & Anti-Burn DoS**: The supervisor records and checks nonces at consumption time against a persistent nonce store. Candidate matching entries are iterated so malicious unauthenticated junk requests cannot burn legitimate approvals (Anti-Burn DoS protection).

### E. Kernel DACL Process Boundary Protection (UI-to-Daemon Process Memory Isolation & OWNER RIGHTS ACE)
- **Mechanism**: The supervisor daemon calls helm_confinement.harden_current_process() upon initialization. This applies an explicit Windows NT DACL to the process token using PROTECTED_DACL_SECURITY_INFORMATION. It grants the current user's SID (_my_sid()) strictly SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, while omitting PROCESS_VM_READ (0x0010), PROCESS_VM_WRITE (0x0020), PROCESS_VM_OPERATION (0x0008), and PROCESS_DUP_HANDLE (0x0040).
- **OWNER RIGHTS ACE (S-1-3-4)**: In Windows NT security, the object owner normally retains default WRITE_DAC and READ_CONTROL rights even if omitted from the DACL. To prevent a same-user process from opening the supervisor with WRITE_DAC and restoring full access, an explicit OWNER RIGHTS ACE (S-1-3-4) is inserted into the DACL with restricted permissions.
- **Expected effect when configured**: The supervisor DACL is intended to deny selected process-memory and DACL-management rights to ordinary same-user processes. This mechanism does not protect against elevated administrators, kernel compromise, or every same-user attack; any empirical result applies only to its recorded test environment.
- **Threat Boundary Limitation**: An elevated process with SeDebugPrivilege (e.g. running as local administrator or NT AUTHORITY\\SYSTEM) can bypass DACL checks and inspect or modify process memory. Helm runs as a standard user; defense against an already-elevated administrator/rootkit is out of scope.
- **DPAPI Scope & Limitations**: Windows DPAPI (CryptProtectData) protects master vault keys against *other* Windows user accounts on the workstation. However, DPAPI does not protect secrets against other processes running under the *same* user account. Therefore, defense against same-user secret exfiltration relies on OWNER RIGHTS ACE process isolation, owner-only file DACLs, and AppContainer network/filesystem restrictions.

### E.1 Update Signing Key Custody & Verification
- **Cold Storage / HSM Custody**: Maintainer Ed25519 update signing private keys are strictly held offline in cold storage or a secure HSM. No update private signing keys are ever stored, cached, or accessible on the client workstation.
- **Pinned Verification Key**: The client workstation retains only the pinned Ed25519 public verification key (update_verifier.py). Updates cannot be installed without a cryptographically valid signature and monotonic version rollback protection.

### E.2 Egress Classification of helm_http_fetch
- **Strict WRITE_EXEC Classification**: helm_http_fetch is classified WRITE_EXEC (not READ_ONLY). Outbound HTTP operations can induce state changes on external servers and transmit data. Egress is guarded by strict SSRF filtering, loopback / link-local metadata blocking, and explicit human confirmation before dispatch.

- **Mechanism**: The supervisor daemon calls `helm_confinement.harden_current_process()` upon initialization. This applies an explicit Windows NT DACL to the process token using `PROTECTED_DACL_SECURITY_INFORMATION`. It grants the current user's SID (`_my_sid()`) strictly `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE`, while omitting `PROCESS_VM_READ` (0x0010), `PROCESS_VM_WRITE` (0x0020), `PROCESS_VM_OPERATION` (0x0008), and `PROCESS_DUP_HANDLE` (0x0040).

### F. Supervisor-Spawned Worker Architecture & Atomic Job Object Lifecycle
- **Mechanism**: The Policy Supervisor daemon (`helm_supervisor_daemon.py`) directly creates the inherited IPC duplex pair and spawns the confined worker process (`helm_worker.py`) in an AppContainer sandbox assigned to a Windows Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- **Authoritative Process Custody**: The supervisor records `authorized_worker_pid` and `authorized_worker_ctime` directly from the OS kernel creation event. The UI never spawns or claims the worker identity; the supervisor conveys `worker_pid` to the UI upon registration.
- **Atomic Termination**: If the supervisor daemon crashes, is killed, or encounters a dirty state, the Windows NT kernel automatically and atomically terminates the worker process via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, guaranteeing zero orphaned worker processes.

### G. Per-Session Monotonic Sequence Tracking on Named Pipe Server
- **Mechanism**: The supervisor's named pipe server tracks client sequence numbers on a per-connection basis (`conn_{pipe_handle}`) rather than a single global counter.
- **Expected effect when configured**: Sequence locking is intended to serialize concurrent clients and prevent replay-state races. This behavior needs ongoing concurrency testing in the shipped process topology.

---

## 4. Explicit Non-Guarantees & Out-of-Scope Risks

The following attack vectors are outside Helm's threat model and cannot be mitigated at the application layer:

1. **Kernel Compromise (Ring 0 / Rootkits)**: If malicious code executes at the kernel level, all Windows OS access checks, tokens, and DACLs are bypassable.
2. **Pre-Existing Host Malware Running as Same User**: If unsandboxed malware is already running with standard user rights outside Helm prior to launch, it can manipulate unhardened user files.
3. **Physical Console Access / Hardware Keyloggers**: A physical hardware device attached between keyboard and motherboard (or physical access to an unlocked workstation) bypasses software controls.
4. **Virtual HID Microcontrollers**: A malicious USB dongle (e.g. Rubber Ducky) presenting as real hardware at the USB HID layer generates genuine hardware scan codes that lack the `LLKHF_INJECTED` flag.
5. **Remote Desktop (RDP) Sessions**: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` excludes windows from local GDI/DWM screen grabs, but does NOT prevent an authenticated remote user on an active RDP connection from viewing the render target. Therefore, pairing code entry assumes the host is attended directly by the physical console operator.
6. **Compromised Enrolled Device**: If an enrolled device's private signing key is compromised, an attacker may be able to create approval evidence until that device is revoked.
7. **Upstream LLM Provider as Data Recipient**: Foundation model providers (Google, Anthropic, OpenAI, NVIDIA) receive prompt text and screen metadata needed to perform tasks. While OS kernel confinement and complete mediation prevent returned responses from executing unapproved side-effects, privacy depends on provider data retention policies.
8. **Supervisor Running as Standard User**: The supervisor runs as a standard Windows user (non-elevated). It does not require Administrative privileges, preventing privilege escalation from compromising system-wide OS integrity.
9. **Remote and Messaging Integrations**: Legacy phone-gateway start/status commands are retired. If configured, Telegram and other remote integrations may send user-provided requests or action details to their service. Supervisor-protected consequential actions still require enrolled-device signatures; messaging does not bypass that check.
10. **Backup & Restore of Cryptographic Keys**: Vault master keys (`.helm_vault.key`) and device registries (`.helm_device_keys.json`) are stored locally with owner-only DACLs. If deleted or lost, stored vault data cannot be recovered without a secure offline backup.
