# Security and limitations

## Intended use and threat model

For authorised responders examining a Mac that may be compromised. An attacker may have altered files, logs and
configuration, so all collected content is **untrusted input**: parsed statically (plists with `plistlib`, YAML with
`safe_load`), size-bounded, never executed, never used to build commands.

Safeguards: argument-array subprocesses (no shell, including the `log show --predicate` string) with timeouts and output
caps; `lstat`-based metadata (symlinks not followed); exclusive file creation with `O_NOFOLLOW`; manifest path-traversal
checks; regex length/nesting limits; redaction of secrets in command lines, launchd arguments, cron/startup commands, log
messages and reports; no network access.

## Privacy

Evidence contains usernames, hostnames, IPs, process command lines, launch-item definitions and log excerpts. Redaction is
pattern-based and best effort. Never collected: keychains, private keys, browser profiles, home-directory contents,
password hashes (`/etc/master.passwd` is metadata only). Treat evidence as sensitive personal and organisational data.

## Privileges and macOS protections

The toolkit never calls `sudo` and never tries to bypass SIP, TCC, Gatekeeper, FileVault or Full Disk Access.
The walkthrough does not require disabling any security setting, granting Full Disk Access, or entering credentials.

| Source | Unprivileged | Administrator / extra permission would add |
|---|---|---|
| Processes (`ps`) | all processes, command lines | hashes of executables in protected locations |
| Sockets (`lsof`) | your processes | other users' and system daemons' sockets |
| Unified log | often only your own / limited | system-wide sshd/sudo events |
| launchd | `/Library`, `~/Library`, `/System/Library` (read) | – |
| Cron | current user's `crontab -l` | `/var/at/tabs` for all users |
| Login Items / Background Task Management | artifact file metadata only | `sfltool dumpbtm` (not used) |

## Modern persistence: what is *not* covered

Login items and background-task registrations (BTM database), configuration profiles/MDM, kernel and system extensions,
authorization plugins, `periodic` hooks other than listing, browser extensions, application-specific updaters, Folder
Actions, dylib hijacking, and anything stored in SIP/TCC-protected or encrypted containers. Protected locations and
permissions vary by macOS version, so identical commands can yield different coverage on different Macs.

## Blind spots

- Live collection is not a disk image; no memory, unallocated space or deleted-file recovery.
- Kernel-level malware and tampering with `ps`/`lsof`/`log` output are not detectable from user space.
- Unified log: events may be omitted, expired, redacted (`<private>`) or restricted; the artifact is a bounded sample.
- `ps lstart` and log timestamps are interpreted as UTC unless stated; host clock accuracy is not verified.
- Code signing is *context*: unsigned ≠ malicious, signed ≠ benign (`codesign` output is not independently validated).
- Rosetta/x86_64 Python on Apple silicon reports `x86_64` from `platform`; the inventory uses `uname -m` and a Rosetta flag.
- An IOC match is not a confirmed compromise; "no findings" is not "clean".

## Validation status (v0.1.0)

| Check | Status |
|---|---|
| Unit tests (parsers, collectors against fake root + mocked `ps`/`lsof`/`log`/`codesign` output), detections, IOC, manifest, reports, CLI, docs checks | Run and passing on Linux (Ubuntu 24.04, Python 3.13) |
| Ruff lint + format, mypy | Run and passing on Linux |
| Real-Mac execution (live `collect` on macOS 12–15, arm64 and x86_64), macOS-only integration tests | **Not run in this environment**; planned CI job on `macos-latest` |
| Exact output formats of `log show --style ndjson`, `lsof -F`, `socketfilterfw` on every macOS version | **Unverified**; parsers are defensive and report malformed lines, but verify on your OS version |
| GitHub Actions workflows | Written, **not executed** here |
