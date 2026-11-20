# Security Notes

> [!IMPORTANT]
> For the full threat model, attack surface analysis, and in-scope/out-of-scope guarantees, see [`THREAT_MODEL.md`](./THREAT_MODEL.md).
> Approval behavior is route-specific. These notes do not claim every protected action uses Windows Hello or that test collection proves execution.
> Numeric results refer only to the named test harness and its recorded run; they are not product-wide release guarantees.
> This document summarizes source mechanisms and named harnesses. It is not an independent security audit or a certification of a published release.

---

## Table of Contents

1. [Sensitive Key Files](#sensitive-key-files)
2. [Security Architecture Overview](#security-architecture-overview)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Threat Model Summary](#threat-model-summary)
5. [Responsible Disclosure](#responsible-disclosure)
6. [Archive Directory](#archive-directory)

---

## Sensitive Key Files

The following files must **NOT** remain in the repository root or be committed to version control:

| File | Purpose |
|------|---------|
| `.helm_vault.key` | Crypto vault encryption key |
| `.helm_session.token` | Active session token |
| `.helm_ledger_hmac.key` | Audit ledger HMAC signing key |

> [!CAUTION]
> Ensure all three files above are listed in `.gitignore` to prevent accidental commits.

### Production Guidance

In production deployments, these files must be stored in the Windows user's protected app data directory:

```
%LOCALAPPDATA%\Helm\keys\
```

Full paths:

```
C:\Users\<username>\AppData\Local\Helm\keys\.helm_vault.key
C:\Users\<username>\AppData\Local\Helm\keys\.helm_session.token
C:\Users\<username>\AppData\Local\Helm\keys\.helm_ledger_hmac.key
```

This directory is per-user, not synced by default (not included in roaming profiles), and is outside the project tree.

---

## Security Architecture Overview

Helm uses a **defense-in-depth** architecture with multiple independent, kernel-enforced layers. No single layer is relied upon alone.

### Layer 1 — Process Isolation (Worker Confinement)

| Mechanism | Detail |
|-----------|--------|
| **AppContainer LowBox Token** | Zero-capability token; network isolation is kernel-enforced. All outbound socket attempts from the worker process fail with `WinError 10013 WSAEACCES`. |
| **Job Object sandbox** | When the worker is assigned to the configured job, `KILL_ON_JOB_CLOSE` requests termination on job-handle closure, `ActiveProcessLimit=1` limits child processes, and UI restrictions limit selected clipboard and desktop access. No general kill-latency figure is claimed. |
| **Supervisor daemon** | Out-of-process supervisor runs as a standard (non-elevated) user and holds custody of the worker process. The worker cannot escape or elevate. |
| **No write-up / no UI handles** | The worker has zero ability to write to higher-integrity contexts or acquire UI-accessible handles. |

### Layer 2 — Filesystem ACLs (Owner-Only DACLs)

Owner-only DACLs (kernel-level deny entries) are applied to:

- Vault key file
- Ledger HMAC key file
- Dirty flag sentinel
- MCP registry
- Audit ledger

These denials are enforced by the kernel even if the supervisor process closes its own handles — a compromised supervisor cannot grant access.

### Layer 3 — Authentication & Elevation Gates

#### Gate 1 — Route-specific Windows Hello check (`helm.core.windows_hello`)

| Property | Value |
|----------|-------|
| Verification methods | Windows-managed options depend on device and account configuration; this may include a PIN, face, or fingerprint |
| Windows Platform API | `Windows.Security.Credentials.UI.UserConsentVerifier` |
| Verification Scope | Selected local approval routes; not every protected action |
| Unavailable behavior | The broker denies the action unless an explicit fallback approver is configured |
| Supervisor relationship | A Windows Hello result does not replace the signed enrolled-device evidence required by the supervisor |

#### Gate 2 — Injection Baseline Harness (`helm.engine.injection_baseline_harness`)

| Property | Value |
|----------|-------|
| Adversarial artifacts | 300 |
| Attack modalities | 7 |
| Confidence interval | 95% Wilson CI |
| Policy-Level Attack Success Rate (ASR) | **0.00%** (CI: 0.00% – 1.26%) |

### Layer 4 — Session & Taint Tracking

- **`taint_tracker.py`**: Tags the session as tainted upon any untrusted input. Tainted sessions require step-up authentication before write operations are permitted.
- **Rails system**: Per-action confirmation, content boundary enforcement, audit trail, and a proactive kill switch.

### Layer 5 — Audit & Integrity

- **`agent_audit_ledger.py`**: Every tool invocation is recorded in a SHA-256 hash-chained, HMAC-signed ledger. Tampering with any entry breaks the chain and is immediately detectable.
- **Named pipe IPC**: Inter-process communication uses owner-only DACLs on the pipe and per-session monotonic sequence counters to prevent replay attacks.

### Layer 6 — Cryptographic Vault

- **`crypto_vault.py`**: All local secrets are encrypted at rest in the vault. The vault key itself is stored outside the project tree (see [Sensitive Key Files](#sensitive-key-files)).

### Layer 7 — Network Protection

- **`helm_ssrf.py`**: HTTP fetch requests are validated before dispatch; loopback addresses, link-local ranges, and cloud metadata endpoints (e.g., `169.254.169.254`) are blocked.
- **AppContainer zero-network**: Worker-level network calls are blocked at the kernel before SSRF filtering is even reached (defense in depth).

### Layer 8 — Input Integrity

- **`WH_KEYBOARD_LL` watchdog**: Low-level keyboard hook rejects synthetic keystrokes flagged with `LLKHF_INJECTED` or `LLKHF_LOWER_IL_INJECTED`. Only physically generated keystrokes can trigger the kill hotkey.

### Layer 9 — Update Integrity

- **Update verifier**: Software updates are verified against **Ed25519-signed manifests** with monotonic epoch rollback protection. Downgrade attacks are rejected.

### Layer 10 — Windows Hello Integration

- **`action_broker.py`**: The broker selects Windows Hello for medium- and high-risk actions. The gate fails closed when Hello is unavailable unless an explicit fallback approver is configured.
- **`helm_supervisor.py`**: Protected consequential actions require a cryptographically signed approval from an enrolled device. The supervisor denies these actions when no device is enrolled, even if a separate local confirmation route exists.
- **`rails_confirmation.py`**: Windows Hello is an optional local step-up only; it does not replace enrolled-device evidence. Local presence gestures do not authorize supervisor-protected actions.

### Layer 11 — Red Team & Mutation Testing

| Test Suite | Result |
|------------|--------|
| Adversarial red team (`adversarial_red_team.py`) | Passed |
| Semantic red team | Passed |
| Model-level red team | Passed |
| Security mutation harness | **112/112 mutations killed (100% kill rate)** |

---

## Cryptographic Primitives

| Primitive | Usage |
|-----------|-------|
| **Ed25519** | Pinned publisher update manifest signatures (`helm.core.update_verifier`) |
| **AES-256-GCM** | Symmetric authenticated encryption of secrets and credentials at rest (`helm.core.crypto_vault`) |
| **SHA-256** | File integrity hashing, update payload validation, and audit ledger hash chaining |
| **HMAC-SHA-256** | Tamper-evident audit ledger per-entry message authentication (`.helm_ledger_hmac.key`) |

---

## Threat Model Summary

> See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the complete threat model, attack trees, and mitigations.

### In Scope (Defended)

- Prompt injection and indirect injection across 7 modalities (0.00% policy-level ASR)
- Unauthorized tool invocations (audit ledger, rails, Windows Hello biometric gates)
- Network exfiltration from the worker process (AppContainer zero-network)
- Replay attacks on IPC (monotonic counters and nonce stores)
- Synthetic keystroke injection (WH_KEYBOARD_LL low-level physical filter)
- Malicious software updates (Ed25519 signed manifests + rollback protection)
- Lateral movement via SSRF (helm_ssrf.py + AppContainer)
- Secrets exposure (owner-only DACLs, encrypted vault, gitignore)

### Explicit Non-Guarantees (Out of Scope)

> [!WARNING]
> The following are **not** defended by this architecture:

- **Kernel compromise** — a compromised OS kernel can bypass all userspace and even AppContainer controls.
- **Pre-existing same-user malware** — malware already running as the same Windows user shares the same DACL access level.
- **Physical console access** — an attacker with physical access to an unlocked console session is out of scope.
- **Virtual HID devices** (e.g., Rubber Ducky, O.MG Cable) — hardware-level HID injection bypasses the `LLKHF_INJECTED` software filter.
- **RDP sessions** — remote desktop sessions may alter keyboard flag semantics.
- **Compromised enrolled device** — a compromised enrolled-device signing key may allow forged approval evidence until that device is revoked.
- **Upstream LLM provider data retention** — data sent to the LLM API is subject to the provider's own privacy and retention policies.

---

## Responsible Disclosure

We take security seriously and appreciate responsible disclosure from the security community.

**If you discover a security vulnerability in this project:**

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. **Email** the maintainers directly with a description of the vulnerability, steps to reproduce, and potential impact. (Add contact email here before publishing.)
3. **Allow reasonable time** (90 days is standard) for the maintainers to assess and patch the issue before public disclosure.
4. **Coordinate disclosure** — we will work with you to understand the issue and credit you in the fix unless you prefer to remain anonymous.

We follow the [CERT/CC 90-day coordinated vulnerability disclosure policy](https://www.kb.cert.org/vuls/govdisclosure/) as a guideline.

---

## Archive Directory

The `archive/` directory contains historical batch scripts and screenshots that were previously cluttering the repository root. These are kept for reference only and are **not** part of the active application. No security-sensitive material should be placed in `archive/`.
