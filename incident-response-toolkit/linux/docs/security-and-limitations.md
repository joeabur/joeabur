# Security and limitations

## Intended use and threat model

For authorised responders examining a host that may be compromised. The toolkit assumes an attacker may have altered
files, logs and configuration; therefore all collected content is treated as **untrusted input**: parsed statically,
size-bounded, never executed, never used to build commands.

Safeguards: argument-array subprocesses (no shell) with timeouts and output caps; `lstat`-based metadata (symlinks not
followed); exclusive file creation with `O_NOFOLLOW`; path-traversal checks for manifest entries; `yaml.safe_load` for
rules, IOCs and config; regex length/nesting limits; redaction of secrets in command lines, cron commands, startup
files, log messages and reports; no network access of any kind.

## Privacy

Evidence contains usernames, hostnames, IP addresses, command lines, cron jobs, SSH key fingerprints and log excerpts.
Redaction is pattern-based and best effort: secrets in unusual formats may remain. Store and share evidence under your
organisation's data-handling rules. Never collect private keys, `/etc/shadow` contents, browser profiles or credential
stores (the toolkit does not; `shadow` metadata only). `authorized_keys` comments are not stored, only key type and a
SHA-256 fingerprint.

## Privileges

| Source | Unprivileged | Needs root (optional) |
|---|---|---|
| Processes | cmdline/stat of most processes; exe for own | exe link/hash of other users' processes |
| Sockets | listeners and own process names | all process↔socket associations |
| Logs | `journalctl` per permissions | `/var/log/auth.log`, `secure`, full journal |
| Firewall (`extended`) | – | `nft`, `iptables` |
| Persistence | `/etc`, `/usr/lib` units, cron.d | user crontabs, `at` spool, `/root/.ssh` |

The tool **never calls sudo**. You decide whether to rerun a specific collector as root.

## Blind spots

- Live collection is not a disk image; no memory, unallocated space or deleted-file recovery.
- Kernel rootkits/eBPF tampering can hide processes, sockets and files from user-space reads.
- Container/namespace visibility: inside a container `/proc` and logs reflect that container only.
- Syslog lines lack year and zone (UTC assumed); host clock accuracy is not verified.
- Journal and auth logs may be rotated, remote-forwarded or disabled by an attacker.
- Persistence coverage is selective (e.g. no PAM, udev, LD_LIBRARY_PATH in unit environments, XDG autostart, package scripts).
- Heuristics produce false positives (each finding lists common ones) and false negatives.
- An IOC match is not a confirmed compromise; "no findings" is not "clean".

## Validation status (v0.1.0)

| Check | Status |
|---|---|
| Unit/integration tests (pytest), Ruff lint+format, mypy | Run and passing on Ubuntu 24.04 / Python 3.13 (see CHANGELOG/CI) |
| Live collection on Ubuntu 24.04 container (non-systemd PID 1, root, no `ss`/`ip`) | Exercised manually; fallbacks verified |
| Live collection on systemd hosts (Ubuntu/Debian/Fedora), ARM64, unprivileged user | **Not tested here**; covered only by synthetic fake-root tests |
| GitHub Actions workflows | Written, **not executed** in this environment |
