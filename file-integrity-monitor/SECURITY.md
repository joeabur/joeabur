# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report privately through GitHub
"Report a vulnerability" (Security tab of the repository) or by email to
markjoejay1960@gmail.com with: affected version/commit, reproduction steps, impact, and any
suggested fix. Expect an acknowledgement within 5 working days. Please allow a reasonable
coordinated-disclosure window before publishing.

## Scope

In scope: the `fim` package, `scripts/`, `systemd/` units and documentation claims, e.g. path
handling flaws, symlink/TOCTOU issues, baseline or signature bypasses, unsafe file writes, injection
into CSV/syslog/CEF output, dependency problems.

Out of scope: attacks that require an attacker who already controls the monitored host **and** the
signing key (documented as a fundamental limit in
[docs/security-and-limitations.md](docs/security-and-limitations.md)).

## Supported versions

Only the latest release on the default branch receives fixes.

## Handling secrets

Never commit private keys, passphrases or real baselines. `.gitignore` excludes `*.pem`, `*.key`;
CI runs secret scanning (gitleaks). If you committed a key, treat it as compromised and rotate
([docs/user-guide.md](docs/user-guide.md#signing-and-key-management)).
