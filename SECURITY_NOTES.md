# Security Notes

## Sensitive Key Files

The following files must **NOT** remain in the repository root or be committed to version control:

- `.homie_vault.key`
- `.homie_session.token`
- `.homie_ledger_hmac.key`

### Production Guidance

In production deployments, these files should be stored in the Windows user's protected app data directory:

```
%LOCALAPPDATA%\Homie\keys\
```

e.g.:
- `C:\Users\<username>\AppData\Local\Homie\keys\.homie_vault.key`
- `C:\Users\<username>\AppData\Local\Homie\keys\.homie_session.token`
- `C:\Users\<username>\AppData\Local\Homie\keys\.homie_ledger_hmac.key`

This directory is per-user, not synced by default, and not part of the project tree.

> **IMPORTANT**: Ensure `.homie_vault.key`, `.homie_session.token`, and `.homie_ledger_hmac.key` are listed in `.gitignore` to prevent accidental commits.

## Archive Directory

The `archive/` directory contains historical batch scripts and screenshots that were previously cluttering the root. These are kept for reference only and are not part of the active application.
