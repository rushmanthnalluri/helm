# E2E Test Infra: Helm Production Readiness Roadmap

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Tests are designed directly against user requirements from `ORIGINAL_REQUEST.md` and public interface contracts documented in `PROJECT.md`, without coupling to internal private implementation details.
- **Deterministic & Cross-Platform Execution**: Test suites use mock audio hardware, virtual display/frame buffers, and HAL mock providers when hardware devices (microphones, speakers, physical screens) are absent, ensuring 100% test reproducibility across CI/CD, local development, and Windows/Linux/macOS platforms.
- **Methodology**: Systematic 4-tier design:
  - **Tier 1 (Feature Coverage)**: Isolated happy-path validation for every feature (≥5 tests per feature).
  - **Tier 2 (Boundary & Corner Cases)**: Edge conditions, empty/overflow inputs, hardware disconnects, timeout, malformed payloads (≥5 tests per feature).
  - **Tier 3 (Cross-Feature Combinations)**: Multi-component interactions (Voice + Omnibar, Vision + Memory, HAL + Confinement).
  - **Tier 4 (Real-World Application Scenarios)**: End-to-end desktop workflows simulating real user sessions.

## Feature Inventory & Test Mapping

| # | Feature | Requirement | Test Suite File | Tier 1 Target | Tier 2 Target | Tier 3 Target | Tier 4 Target |
|---|---------|-------------|-----------------|:-------------:|:-------------:|:-------------:|:-------------:|
| F1 | OS Abstraction Layer (HAL) Base Interfaces & Factory | R4 | `tests/test_os_abstraction_hal.py` | 5 | 5 | 2 | 2 |
| F2 | Windows HAL Implementation & Linux/macOS/Mock Stubs | R4 | `tests/test_os_abstraction_hal.py` | 5 | 5 | 2 | 2 |
| F3 | Core Engine Decoupling (Zero Direct Win32 Calls) | R4 | `tests/test_os_abstraction_hal.py` | 5 | 5 | 2 | 2 |
| F4 | Full-Duplex Audio Streaming Pipeline | R1 | `tests/test_e2e_voice_duplex.py` | 5 | 5 | 2 | 2 |
| F5 | Silero VAD Barge-in & Audio Interruption | R1 | `tests/test_e2e_voice_duplex.py` | 5 | 5 | 2 | 2 |
| F6 | Low-Latency Neural TTS Cascade | R1 | `tests/test_e2e_voice_duplex.py` | 5 | 5 | 2 | 2 |
| F7 | Audio Error & Disconnect Resilience | R1 | `tests/test_e2e_voice_duplex.py` | 5 | 5 | 2 | 2 |
| F8 | Wake Word Detection (`\bhelm\b`) & Engine Wiring | R1, R5 | `tests/test_e2e_voice_duplex.py` | 5 | 5 | 2 | 2 |
| F9 | Omnibar Indexing & Window Search Navigation | R2 | `tests/test_e2e_omnibar_ipc.py` | 5 | 5 | 2 | 2 |
| F10 | Omnibar PyWebView IPC Bridge & Dispatcher | R2 | `tests/test_e2e_omnibar_ipc.py` | 5 | 5 | 2 | 2 |
| F11 | UI State Synchronization & Hotkey Handlers | R2 | `tests/test_e2e_omnibar_ipc.py` | 5 | 5 | 2 | 2 |
| F12 | Modern Action HUD Styling & Spring Animation Contracts | R2 | `tests/test_e2e_omnibar_ipc.py` | 5 | 5 | 2 | 2 |
| F13 | 64-bit dHash & pHash Perceptual Hashing | R3 | `tests/test_e2e_ambient_perceptual.py` | 5 | 5 | 2 | 2 |
| F14 | Periodic Ambient Screen Sampling Loop | R3 | `tests/test_e2e_ambient_perceptual.py` | 5 | 5 | 2 | 2 |
| F15 | Perceptual Timeline Schema & SQLite Hashing Index | R3 | `tests/test_e2e_ambient_perceptual.py` | 5 | 5 | 2 | 2 |
| F16 | Visual Privacy Safeguards & Sensitive Content Exclusion | R3 | `tests/test_e2e_ambient_perceptual.py` | 5 | 5 | 2 | 2 |
| F17 | Natural Language Visual Timeline Querying | R3 | `tests/test_e2e_ambient_perceptual.py` | 5 | 5 | 2 | 2 |

## Test Architecture & Directory Layout

```
D:\helm\
├── tests\
│   ├── test_helm_upgrades.py            # Existing regression test suite (DAG, Memory, Vault, Confinement)
│   ├── test_os_abstraction_hal.py       # R4: HAL base contracts, platform implementations, stubs, decoupling
│   ├── test_e2e_voice_duplex.py         # R1: Duplex voice, Silero VAD barge-in, TTS streaming, wake word
│   ├── test_e2e_omnibar_ipc.py          # R2: Omnibar window/app indexer, IPC dispatcher, UI contracts, hotkeys
│   └── test_e2e_ambient_perceptual.py   # R3: dHash/pHash 64-bit algorithms, ambient capture, privacy, visual queries
```

### Test Runner Invocation
Full test suite execution:
```bash
python -m pytest tests/ -v
```

Targeted suite execution:
```bash
python -m pytest tests/test_os_abstraction_hal.py -v
python -m pytest tests/test_e2e_voice_duplex.py -v
python -m pytest tests/test_e2e_omnibar_ipc.py -v
python -m pytest tests/test_e2e_ambient_perceptual.py -v
python -m pytest tests/test_helm_upgrades.py -v
```

## Real-World Application Scenarios (Tier 4)
1. **Scenario 1: Hands-Free Voice Assistant Interrupt Loop**: User speaks wake word "Helm", system begins synthesizing voice response; user interrupts mid-sentence with new instruction, Silero VAD detects barge-in within 50ms, stops playback, and accepts new speech stream.
2. **Scenario 2: Floating Omnibar Rapid App Switch & Action Execution**: User activates `Alt+Space`, Omnibar renders with spring animations, user types "notepad", receives instantaneous ranked index results, selects item, and launches action via IPC.
3. **Scenario 3: Ambient Visual Memory Search After Work Session**: Background ambient loop captures frames at regular intervals, hashes each with 64-bit dHash/pHash, stores non-sensitive frames in perceptual index; user asks "What was the error on my screen 10 minutes ago?", system performs natural language search matching historical timeline entry.
4. **Scenario 4: Cross-Platform Core Migration**: Core engine starts up on Linux/macOS with MockHAL / platform stubs without Win32 dependency errors, creating isolated worker processes and managing windows via unified HAL interfaces.

## Minimum Coverage Thresholds
- **Tier 1**: ≥ 5 per feature (85 tests total across 17 features)
- **Tier 2**: ≥ 5 per feature (85 tests total across 17 features)
- **Tier 3**: ≥ 10 cross-feature pairwise interaction tests
- **Tier 4**: ≥ 8 realistic multi-module application scenarios
- **Total Minimum Target**: ~180+ assertions/test cases across the 4 newly created suites, alongside the existing 27 test cases in `test_helm_upgrades.py`.
