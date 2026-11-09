# Homie AI Workstation Assistant: Formal Security Threat Model (Batch 21)

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
|            | IPC Pipe (Inherited Handle Only, No AppContainer Access)|  |
|            v                                                |           |
|  +--------------------+                                     |           |
|  |  Confined Worker   |                                     |           |
|  | (AppContainer,     |<------------------------------------+           |
|  |  Zero Network,     |   win32job.TerminateJobObject                   |
|  |  No Write-Up,      |   Kill Latency < 3ms                            |
|  |  ActiveProcess=1)  |                                                 |
|  +--------------------+                                                 |
+-------------------------------------------------------------------------+
             ^
             | Signed WebAuthn Challenge (HTTPS / Out-of-Band Phone Gateway)
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

### B. Secret & State Storage Protection (Owner-Only Protected DACLs)
- **Mechanism**: Critical assets (`.homie_vault.key`, `ledger_key.bin`, `homie_supervisor_dirty.flag`, `homie_mcp_registry.json`, `homie_audit_ledger.jsonl`) are hardened with owner-only DACLs (`_my_sid()`, `SYSTEM`) and `PROTECTED_DACL_SECURITY_INFORMATION`.
- **Guarantee**: Even when the supervisor closes its file handles, the worker token is strictly denied `GENERIC_READ`, `GENERIC_WRITE`, and `DELETE` by the NT kernel (`PermissionError: [WinError 5] ERROR_ACCESS_DENIED`).
- **Idle Pipe DACL Protection**: Supervisor named pipes created with `_owner_only_dacl` deny unauthenticated connection attempts with `ERROR_ACCESS_DENIED (5)` even when the pipe instance is idle and unconsumed.

### C. Sub-process Fork Bombing & UI Injection Defense (Job Object Sandbox)
- **Mechanism**: Windows Job Object with:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (`ActiveProcessLimit = 1`)
  - `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
  - UI Limits: `UILIMIT_READCLIPBOARD`, `UILIMIT_WRITECLIPBOARD`, `UILIMIT_HANDLES`, `UILIMIT_DESKTOP`.
- **Guarantee**: Worker cannot spawn sub-processes (`OSError: [WinError 1816] ActiveProcessLimit`), cannot read/write system clipboard directly, and cannot open window station handles. Terminating or crashing the supervisor immediately terminates all worker processes.

### D. Hardware Kill Hotkey & Synthetic Keystroke Rejection (Independent Watchdog)
- **Mechanism**: `WH_KEYBOARD_LL` low-level keyboard hook running on a dedicated thread with its own Win32 message loop (`GetMessageW` / `DispatchMessageW`).
- **Guarantee**: Keystrokes flagged with `LLKHF_INJECTED` (0x01) or `LLKHF_LOWER_IL_INJECTED` (0x02) are rejected. Malicious scripts or synthetic `SendInput` cannot trigger or disarm the emergency switch. True kill latency to process death is measured at **< 3ms**.

### E. Screen Capture & Screen-Memory Exclusion (Hardware HUD & Pairing)
- **Mechanism**: Transparent HUD overlay and enrollment pairing windows set `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
- **Guarantee**: OS screen capture APIs (DWM, Snipping Tool, OBS, agent screenshots) render transparent black, preventing screen memory OCR ingestion from leaking one-time enrollment codes or contaminating vision models.

---

## 3. Cryptographic & Mediation Guarantees

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
- **Out-of-Process Supervisor Daemon & Pipe Client Split**: In Batch 41, the Policy Supervisor was decoupled into a dedicated out-of-process daemon (`homie_supervisor_daemon.py`) communicating over Windows Named Pipe `\\.\pipe\homie_supervisor` with kernel-attested client validation (`GetNamedPipeClientProcessId`). The daemon holds exclusive custody of the cryptographic INTENT V2 HMAC signing keys, HMAC-SHA256 audit ledger, and physical actuators. The UI/broker process (`action_broker.py`) operates as a pipe client holding no signing keys, and fails closed immediately across all channels if the supervisor process is unreachable or terminated.
- **Mandatory Mobile Cryptographic Proof (Elimination of Decorative Phone Gate)**: In `rails_confirmation.py`, when a mobile device is enrolled in `device_registry`, `confirm()` strictly requires a cryptographically verified signed approval blob from the enrolled hardware device. Local callers cannot bypass phone authentication. If no device is enrolled, an explicit physical presence gesture (matching an ephemeral challenge code) is required.
- **Hardware Grounding & Anti-DoS ACLs**: Recovery token file DACL explicitly denies `DELETE` permission to standard `Users` SID (`S-1-5-32-545`), preventing unprivileged denial-of-service deletion. Script self-elevation via `ShellExecuteW(runas)` has been removed, eliminating user-space hijacking of user-writable scripts.
- **Evidence-Based Security (Store Evidence, Not a Verdict)**: To ensure integrity against untrusted local worker injection or malicious database writes, the Policy Supervisor never treats row presence or unsigned SQLite boolean flags as an authorization verdict. Every approval requires a full **Signed Approval Blob** containing `{device_id, caller_id, tool_name, args_hash, nonce, expiry, taint_epoch, challenge_seq, signature}`.
- **Asymmetric Signature Verification Against Pinned Authenticator Keys**: When `consume_approved_action` executes, the supervisor independently verifies the Ed25519 or NIST P-256 asymmetric signature against enrolled public keys in `.homie_device_keys.json`. Private signing keys reside exclusively on the user's mobile hardware device (or platform hardware keystore / WebCrypto enclave) and never touch the PC. An attacker manipulating the SQLite database cannot forge valid approvals.
- **Persistent Nonce Single-Use & Anti-Burn DoS**: The supervisor records and checks nonces at consumption time against a persistent nonce store. Candidate matching rows in SQLite are iterated so malicious unauthenticated junk rows cannot burn legitimate approvals (Anti-Burn DoS protection).
- **WebCrypto Browser Keys vs Hardware Platform Keystores**: Phone approval portal web sessions use non-extractable WebCrypto keypairs bound to browser storage. For maximum defense-in-depth, hardware-backed authenticators (FIDO2 WebAuthn / Secure Enclave) bind keys directly to device platform hardware (TPM / Apple Secure Enclave / Android StrongBox), barring key exfiltration even from browser processes.

---

## 4. Explicit Non-Guarantees & Out-of-Scope Risks

The following attack vectors are outside Homie's threat model and cannot be mitigated at the application layer:

1. **Kernel Compromise (Ring 0 / Rootkits)**: If malicious code executes at the kernel level, all Windows OS access checks, tokens, and DACLs are bypassable.
2. **Pre-Existing Host Malware Running as Same User**: If unsandboxed malware is already running with standard user rights outside Homie prior to launch, it can manipulate unhardened user files.
3. **Physical Console Access / Hardware Keyloggers**: A physical hardware device attached between keyboard and motherboard (or physical access to an unlocked workstation) bypasses software controls.
4. **Virtual HID Microcontrollers**: A malicious USB dongle (e.g. Rubber Ducky) presenting as real hardware at the USB HID layer generates genuine hardware scan codes that lack the `LLKHF_INJECTED` flag.
5. **Remote Desktop (RDP) Sessions**: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` excludes windows from local GDI/DWM screen grabs, but does NOT prevent an authenticated remote user on an active RDP connection from viewing the render target. Therefore, pairing code entry assumes the host is attended directly by the physical console operator.
6. **Compromised Mobile Phone / Hardware Authenticator**: If the user's paired mobile device is jailbroken, infected with malware, or its Secure Enclave private key is compromised, forged approvals can be generated.
7. **Upstream LLM Provider as Data Recipient**: Foundation model providers (Google, Anthropic, OpenAI, NVIDIA) receive prompt text and screen metadata needed to perform tasks. While OS kernel confinement and complete mediation prevent returned responses from executing unapproved side-effects, privacy depends on provider data retention policies.
8. **Supervisor Running as Standard User**: The supervisor runs as a standard Windows user (non-elevated). It does not require Administrative privileges, preventing privilege escalation from compromising system-wide OS integrity.
9. **Phone Gateway Network Exposure & Telegram Role**: The Phone Gateway runs on a local loopback/private Wi-Fi interface (or encrypted WireGuard tunnel). Telegram remains only as a secondary notification channel for asynchronous human alerts and cannot bypass phone cryptographic challenge signing.
10. **Backup & Restore of Cryptographic Keys**: Vault master keys (`.homie_vault.key`) and device registries (`.homie_device_keys.json`) are stored locally with owner-only DACLs. If deleted or lost, stored vault data cannot be recovered without a secure offline backup.
