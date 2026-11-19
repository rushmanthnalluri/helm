# 🤝 Contributing to Helm

Thank you for your interest in contributing to **Helm** — an open-source Windows desktop AI assistant built with Python. Whether you're squashing bugs, dreaming up features, or just improving a typo in the docs, every contribution makes Helm smarter, safer, and more useful for everyone. We're glad you're here! 🎉

---

## 🌟 Ways to Contribute

There are many ways to get involved — no contribution is too small:

- 🐛 **Bug Reports** — Found something broken? Open an issue with clear reproduction steps, your OS version, and any relevant logs.
- 💡 **Feature Requests** — Have an idea that would make Helm better? Open a discussion or issue describing the problem you're solving and your proposed approach.
- 🔌 **Plugins** — Extend Helm's capabilities by writing a new plugin. See [Adding a Plugin](#-adding-a-plugin) below.
- 📝 **Documentation** — Improve README files, add docstrings, write guides, or fix typos. Great docs are a superpower.
- 🌐 **Translations** — Help make Helm accessible to more users by contributing locale strings.
- 🔬 **Tests** — Add test coverage for untested paths, edge cases, or new features.

---

## 🛠 Development Setup

### Prerequisites

- **Windows 10 or Windows 11** (required — Helm uses Windows-native APIs)
- **Python 3.10 or later** (Python 3.14 recommended to match CI)
- **Git**

### Getting Started

```powershell
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-username>/helm.git
cd helm

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the desktop GUI
python app.py

# 5. Or run the CLI brain
python helm.py

# 6. Or launch the terminal chat interface
python chat_cli.py
```

> [!NOTE]
> Configuration lives at `%USERPROFILE%\.config\helm\settings.json`. You can also override most settings via environment variables. See the README for details.

---

## 🧪 Running Tests

Helm has a comprehensive test suite with **350+ tests across 90+ test files**.

### Run the Full Suite

```powershell
python -m pytest -q
```

### Run a Focused Subset

```powershell
# Run a specific test file
python -m pytest tests/test_voice_pipeline.py -q

# Run tests matching a keyword
python -m pytest -k "webauthn" -q

# Run with verbose output
python -m pytest -v
```

### What the Tests Cover

| Area | Description |
|---|---|
| Fast commands | Core command dispatch and response logic |
| Security mutations | Mutation tests for security-critical modules |
| WebAuthn | Passkey / FIDO2 authentication flows |
| Voice pipeline | STT/TTS pipeline integration |
| Injection harness | Prompt injection resistance |
| Omnibar | Universal input and routing |
| Skill compiler | Plugin/skill compilation and loading |
| Semantic memory | Embedding-based memory retrieval |
| Mail & Calendar | Email and calendar integrations |
| Browser automation | Headless browser control |
| Red-team | Adversarial robustness tests |

> [!TIP]
> Run `python -m pytest --co -q` to list all collected tests without executing them — useful for getting your bearings in the suite.

---

## 🎨 Code Style

We recommend the following formatters and linters (they're fast, and your editor probably supports them):

- **[black](https://black.readthedocs.io/)** — opinionated, deterministic Python formatter
- **[ruff](https://docs.astral.sh/ruff/)** — extremely fast linter that covers flake8, isort, and more

```powershell
pip install black ruff

# Format
black .

# Lint
ruff check .
```

**General guidelines:**
- Match the style of the surrounding code when in doubt.
- Keep functions and methods focused; prefer small, testable units.
- Add docstrings to public functions, classes, and modules.
- Avoid clever one-liners that sacrifice readability.

---

## 🔒 Security-Critical Modules

The following modules implement core trust and safety mechanisms. **Any pull request that touches these files must include mutation tests** to demonstrate that the security invariants hold even when code is subtly altered:

| Module | Purpose |
|---|---|
| `webauthn_verifier.py` | FIDO2/WebAuthn credential verification |
| `helm_confinement.py` | Main process sandboxing and confinement |
| `worker_confinement.py` | AppContainer worker sandboxing |
| `rails_*.py` | Safety rails and output filtering |
| `taint_tracker.py` | Taint propagation for untrusted input |
| `step_up_gate.py` | Elevated-privilege step-up authentication |
| `agent_audit_ledger.py` | Tamper-evident action audit log |
| `crypto_vault.py` | Secret storage and key management |
| `policy_envelope.py` | Signed policy enforcement |
| `update_verifier.py` | Signed update verification |

> [!CAUTION]
> Do **not** bypass the supervisor ↔ AppContainer worker trust boundary under any circumstances. Changes to the security architecture should be discussed in an issue before any code is written.

Please also review `THREAT_MODEL.md` for a full description of the trust model, attack surface, and security assumptions before making changes to any of these modules.

**Running mutation tests:**

```powershell
# Example using mutmut (adjust to your mutation testing setup)
python -m pytest tests/test_security_mutations.py -q
```

---

## 🔌 Adding a Plugin

Helm's plugin system lives in `helm_plugins.py` and the `plugins/` directory. The best reference implementation is the **Spotify plugin**:

```
plugins/
└── spotify/
    ├── manifest.json   ← plugin metadata and capability declarations
    └── plugin.py       ← plugin implementation
```

### `manifest.json`

Declares the plugin's identity, version, required permissions, and the intents it handles:

```json
{
  "name": "spotify",
  "version": "1.0.0",
  "description": "Control Spotify playback via Helm.",
  "permissions": ["network"],
  "intents": ["play_music", "pause_music", "skip_track"]
}
```

### `plugin.py`

Implements the intent handlers that Helm dispatches to:

```python
class SpotifyPlugin:
    def play_music(self, context):
        ...
```

> [!IMPORTANT]
> Plugins run outside the security-critical core. Do not access `crypto_vault.py`, `agent_audit_ledger.py`, or any confinement module from plugin code. Declare all required permissions in `manifest.json`.

Open an issue to discuss your plugin idea before building something large — we can give early design feedback and help it land faster.

---

## 📬 Pull Request Guidelines

- **Keep PRs small and focused.** One feature or fix per PR makes review faster and merging safer.
- **Describe what and why**, not just how. A good PR description explains the problem being solved.
- **Link related issues** using `Closes #123` or `Fixes #123` in the PR description.
- **Add or update tests** for any behaviour you change or introduce.
- **Update documentation** (README, docstrings, comments) when you change the user-visible behaviour.
- **Never commit secrets.** See [Secrets to Never Commit](#secrets-to-never-commit) below.
- Keep CI green — all checks must pass before a PR can be merged.

### Secrets to Never Commit

The following files and patterns must **never** appear in a commit:

- `.helm_vault.key`
- `.helm_session.token`
- `.helm_ledger_hmac.key`
- `.env`
- API keys, tokens, or passwords of any kind

If you accidentally commit a secret, treat it as compromised and rotate it immediately. Use `git filter-repo` or contact the maintainers for help cleaning the history.

---

## 💬 Commit Message Style

We follow **[Conventional Commits](https://www.conventionalcommits.org/)** to keep the history readable and changelog generation automatic:

```
<type>(<optional scope>): <short summary>

[optional body]

[optional footer(s)]
```

### Common Types

| Type | When to use |
|---|---|
| `feat:` | A new feature |
| `fix:` | A bug fix |
| `docs:` | Documentation only changes |
| `test:` | Adding or updating tests |
| `security:` | A security fix or hardening change |
| `refactor:` | Code change that is neither a fix nor a feature |
| `chore:` | Build process, dependency updates, tooling |
| `perf:` | A performance improvement |

**Examples:**

```
feat(plugins): add Spotify plugin with playback control
fix(webauthn): reject credentials with expired timestamps
docs(contributing): add mutation test instructions
security(crypto_vault): rotate key derivation to Argon2id
```

---

## 🚨 Reporting Security Vulnerabilities

**Please do not report security vulnerabilities as public GitHub issues.**

If you discover a security vulnerability in Helm:

1. **GitHub Security Advisories (preferred):** Open a [private security advisory](https://github.com/your-org/helm/security/advisories/new) on the repository. This keeps the report confidential until a fix is ready.
2. **Email:** Send details to the maintainers via the security contact listed in `SECURITY.md`.

Please include:
- A description of the vulnerability and its potential impact
- Reproduction steps or a minimal proof-of-concept
- Affected versions or modules

We aim to acknowledge reports within **48 hours** and to coordinate disclosure with you. Thank you for helping keep Helm and its users safe. 🛡️

---

## 📄 License

Helm is released under the **MIT License**. By contributing, you agree that your contributions will be licensed under the same MIT License that covers the project.

See [`LICENSE`](./LICENSE) for the full license text.

---

*Happy hacking! If you have any questions, feel free to open a discussion or reach out in the community chat. We're excited to build Helm with you.* 🏠✨
