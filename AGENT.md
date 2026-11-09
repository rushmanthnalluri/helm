# Homie agent mission

## Mission

Build a dependable personal, voice-first assistant with one shared agent core for text, voice, tools, durable memory, and proactive workflows. Keep action execution visible and enforce explicit safety controls.

## Product identity

The assistant name is configurable. **Homie** is the current product name; **Trillion** remains a temporary codename from the product brief and is not a dependency.

## Initial operating assumptions

- Single user, laptop first, and text first for new agent capabilities.
- Push to talk is the initial voice interaction; wake word remains optional.
- Proactive behavior is enabled but quiet by default.

## Engineering principles

- Keep a small shared core and put model providers, speech, tools, persistence, scheduling, and interfaces behind focused seams.
- Validate typed tool inputs, apply explicit permissions, and make execution observable.
- Persist durable state, distinguish data from instructions, and report an action complete only after verifying its result.
- Deliver one runnable tier at a time and preserve working interfaces.

## Configuration and secrets

- Keep provider credentials in environment variables (`GEMINI_API_KEY`, `NVIDIA_API_KEY`, or `GROQ_API_KEY`) or the existing ignored per-user settings file. Never commit credentials.
- Use `.env.example` only for placeholder names and safe setup guidance; `.env` and `.env.*` are ignored.
- Existing app preferences live in `%USERPROFILE%\.config\homie\settings.json` (or `%HOMIE_DIR%`). This legacy file can contain provider keys; prefer environment variables for new setup.
- Root `.key` files, device key JSON, and other local security state are ignored by Git.

## Current state (2026-11-09)

### Repository and runtime

- Python 3.14 on Windows; existing app uses PyWebView, `pynput`, local Whisper, and native Windows automation.
- `app.py` is the desktop voice/UI entry point; `homie.py` handles fast command routing and persistent preferences; `ai_engine.py` dispatches Gemini and OpenAI-compatible providers and tool calls.
- `voice.py`, `action_broker.py`, `memory` helpers, the timeline, and safety modules already cover parts of later tiers. Do not duplicate those systems when extending the agent.
- Dependencies are listed in `requirements.txt`. The regression command is `python -m pytest -q`; pytest loads `tests/conftest.py`, which resets safety state between tests.
- Runtime provider settings and keys are present in the user's per-user settings file; keys are not stored in this repository. A live Gemini terminal session was verified on 2026-11-09; other providers were not exercised live.
- Verified 2026-11-09: `python -m pytest -q` — 350 passed (one upstream `aifc` deprecation warning); focused Tier 1-6 suites — 54 passed; `python -m py_compile app.py agent_tools.py chat_core.py chat_cli.py voice.py durable_memory.py heartbeat_service.py rails_config.py rails_confirmation.py rails_content_boundary.py rails_audit.py` — passed. Live Gemini text recall and real ActionBroker vitals call succeeded.

### Tier status

- Tier 0: repository assessed; mission, assumptions, configuration, and known state are recorded here. `.gitignore` protects local environment files and existing key artifacts.
- Tier 1: complete. Terminal conversation uses a streaming provider seam, in-session history, configurable assistant name, mission prompt, and recoverable failures. Five focused tests and the full 310-test pytest suite pass. In a live Gemini terminal session, Homie recalled “amber” from the first message after three intervening turns.
- Tier 2: complete. The registry exposes only `homie_get_vitals` and `homie_list_downloads`, validates arguments, applies timeouts, caps tool rounds/results, logs tool outcomes without content, and routes execution through ActionBroker. Gemini completed a deterministic tool round-trip, and a real workstation vitals call succeeded after the test isolation fixture cleared the stale marker. No recovery safeguard was bypassed.
- Tier 3: implementation is integrated, physical acceptance pending. Desktop typed asks and push-to-talk transcripts use the same AgentCore, with local Whisper input, visible transcript, a compact PyWebView chat window, queued Windows SAPI speech, and interruption through the existing recording path. The Windows UI uses a PyWebView-compatible bridge, a native resizable frame, and a minimize control. Focused UI/voice regressions pass (9 passed), and the changed modules compile. Windows enumerated a default microphone array and Realtek speaker; no audio was captured or played during verification.
- Tier 4: complete and verified. `durable_memory.py` provides human-editable JSON persistence (`facts.json`), atomic read/write, length/count bounds (max 50 facts, max 64 char keys, max 500 char facts), dynamic prompt context formatting, and least-privilege tools (`homie_remember_fact`, `homie_forget_fact`, `homie_list_facts`). Verified with 6/6 tests passing in `tests/test_durable_memory.py`.
- Tier 5: complete and verified. `heartbeat_service.py` provides background periodic checks (`heartbeat_checks.json`), schedule due time persistence across restarts (`heartbeat_state.json`), quiet-hours policy, held catch-up inbox (`heartbeat_inbox.json`), dismissible alerts, anti-overlap locks, and emergency kill switch integration. Wired into desktop app lifecycle. Verified with 7/7 tests passing in `tests/test_heartbeat_service.py`.
- Tier 6: complete and verified. Centralized configuration (`rails_config.py` / `homie_config.json`) with instant mtime hot-reloading; hard confirmation gate on consequential actions (`rails_confirmation.py`) with per-action single-use tokens and plain-English impact statements; untrusted-content boundary (`rails_content_boundary.py`) with data-not-commands wrapping and planted instruction detection/flagging; visible audit trail and running cost/token tally (`rails_audit.py`); emergency kill switch halts proactive checks and tools while keeping plain text conversation fully functional. Verified with 6/6 tests passing in `tests/test_rails_safety.py`.
- Tier 7 (Hardened Confinement & Complete Mediation): complete and verified. Out-of-process supervisor daemon (`homie_supervisor_daemon.py`), low-privilege worker AppContainer confinement (`worker_confinement.py`), OWNER RIGHTS ACE (`S-1-3-4`) DACL deny, fail-closed foreground tracking (`get_foreground_window` PID/image check), and zero bearer token IPC authorization over named pipe. Verified across 106 security mutants.
- Tier 8 (Physical WebAuthn & Dual-Gated Write Automation): complete and verified.
  * Gate 1 Physical Phone WebAuthn Verifier (`webauthn_verifier.py`): In-supervisor verification of ES256 and Ed25519 WebAuthn assertions; challenge bound to 32-byte SHA-256 of canonical approval object; device-bound enforcement (rejects `BE=1` synced passkeys); UP/UV verification; monotonic sign counter rollback protection. Verified with 12/12 tests in `tests/test_webauthn_verifier.py`.
  * Gate 2 Baseline Injection Evaluation Harness (`injection_baseline_harness.py`): 300 adversarial artifacts across 7 modalities with 30% held-out test split, reporting 95% Wilson confidence intervals. 0.00% Policy-Level ASR (0.00% - 1.26% CI), 100.0% clean task success rate. Verified with 4/4 tests in `tests/test_injection_baseline_harness.py`.
  * Tier B Mail & Calendar Write Halves (`homie_mail_calendar.py`): Outbound send and attendee invites require WebAuthn verification, idempotency keys, Sent folder auditing, and recipient policy checks. Verified with 12/12 tests in `tests/test_mail_calendar.py`.
  * Tier C Browser Automation Write Halves (`homie_browser_broker.py`): Gated form submit requires WebAuthn assertion verification and anti-TOCTOU DOM mutation check. Verified with 7/7 tests in `tests/test_browser_broker.py`.
  * CI Mutation Test Harness: 112/112 security mutations killed (100.0% kill rate).

### Known risks and gaps

- The existing provider engine is primarily single-prompt and tool-oriented. `chat_core.py` now provides a history-aware streaming adapter and bounded read-only tool loop for terminal and desktop turns.
- Existing UI/voice, remote-control, and tool pathways are broad; each future tier must verify shared-core routing and the current safety gates rather than infer integration from module presence.
- Existing settings support plaintext provider keys for backward compatibility. Keep new credential guidance environment-based and retain the settings file outside the repository.
- Physical microphone/speaker behavior has not yet been exercised in this session. Passing mocked integration tests does not prove that the selected Windows audio devices work.
- There are pre-existing uncommitted changes in security modules and tests at mission start. Preserve those changes; inspect `git status` before editing shared files. A leftover mutation-test bypass in `phone_approval_portal.py` was restored to its adjacent backup's signature-verification condition after the existing security test exposed it.

## Delivery plan

1. **Tier 0 — Baseline:** document the actual stack, configuration, test command, risks, and milestone status. Acceptance: this file reflects repository evidence, secrets remain ignored, and the baseline command is known.
2. **Tier 1 — Text brain:** add a terminal chat using a shared in-memory turn history, configurable name and mission prompt, streaming provider seam, and recoverable errors. Acceptance: focused tests prove history and stream handling; the documented test suite passes; a live terminal exchange recalls an earlier turn.
3. **Tier 2 — Tools:** reuse the existing ActionBroker and typed tool contracts behind a registry owned by the shared core. Acceptance: read-only calls, validation, timeouts, and consequential-action gates are demonstrated. Registry, fake-provider, and live workstation vitals checks pass.
4. **Tier 3 — Voice:** route push-to-talk transcripts and spoken output through the Tier 1/2 turn entry point. Code and focused tests are in place; acceptance still requires a physical push-to-talk tool question, spoken result, visible transcript, and interruption check.
5. **Tier 4 — Durable memory:** expose inspectable, bounded facts through persistence and the shared core. Acceptance: a fact survives restart and a human edit is respected.
6. **Tier 5 — Heartbeat:** add quiet, persisted schedules and a dismissible catch-up inbox. Acceptance: checks do not overlap, survive restart, and respect quiet hours and the kill switch.
7. **Tier 6 — Rails:** centralize per-action confirmation, untrusted-content handling, configuration, audit, and proactive kill switch. Acceptance: consequential actions stop for explicit confirmation and proactive work can be paused without disabling conversation.

No material blocker was found for Tier 1. Later tiers should be reassessed against existing modules and their current tests before changes begin.
