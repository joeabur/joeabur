# Security properties and limitations

Read this before relying on FIM. It states what the tool does, what it does **not**, and what
you must add around it.

## The fundamental limit

> **A file integrity monitor running on a host cannot, by itself, guarantee integrity if an
> attacker controls that host.** An attacker with root can modify the monitor, the Python
> environment, the kernel, the configuration, the baseline *and* any signing key stored on the
> machine, or simply feed the scanner lies. Local hashing detects *accidents and unsophisticated
> or noisy tampering*; it does not provide tamper resistance against a determined local root
> attacker.

FIM therefore tries to make tampering **detectable and attributable under stated assumptions**, and
tells you how to move trust off the host.

## What FIM provides

| Property | Mechanism | Holds only if |
|---|---|---|
| Detect added/modified/deleted/permission/owner/type/symlink changes | SHA-256 (streamed) + `lstat` metadata compared with baseline | The host (kernel, Python, FIM) is not compromised during the scan |
| Don't call unverified things clean | Every unreadable/vanished/racing/oversized/unlisted path becomes an issue; exit 3 | n/a |
| Detect baseline corruption or naive edits | Embedded `content_sha256` over the whole body | Attacker does not recompute it |
| Detect baseline forgery | Detached Ed25519 signature checked on every load; unsigned = rejected | The **private key is not available to the attacker** and the configured public key is not replaced |
| Detect baseline rollback or silent replacement | `CURRENT` cross-checked with a hash-chained audit trail; `prev_sha256` chain | The attacker cannot also rewrite `audit.jsonl` consistently |
| Accountable baseline changes | Mandatory reason, confirmation, audit record (user, uid, pid, host, versions, hashes, accepted counts) | Audit trail is forwarded or backed up off-host |
| Safe operation | Read-only scans, `O_NOFOLLOW`, no following of links outside roots unless opted in, no restore/repair, atomic no-overwrite writes, `0700/0600` modes, resource limits | n/a |

## What FIM does *not* provide

* **Prevention.** It reports; it never blocks or reverts changes.
* **Protection from a root attacker on the host** (above). Rootkits, kernel modules, `LD_PRELOAD`,
  a replaced Python, a mocked filesystem, or a tampered `fim` binary defeat any local check.
* **Time-of-check/time-of-use perfection.** Files can change after hashing. Races *during* a scan
  are detected where observable (inode/type swap, size/mtime change), but a change that reverts
  before the scan looks is invisible, as is anything between two scans.
* **Inode reuse caveat.** The `lstat`→`open` identity check compares inode+device; a swap that
  recycles the same inode number with equal size/mtime may not be seen.
* **Content-level semantics.** A file whose bytes are unchanged but which is *interpreted*
  differently (e.g. via a changed mount, ACL, xattr, SELinux label, capability or immutable flag)
  is not detected if it lives outside what FIM records. **Extended attributes (POSIX ACLs, SELinux
  labels, file capabilities, `user.*`) are recorded and compared (as value digests) where the
  filesystem supports them, but immutable/append-only flags (`chattr`), ownership of mount options,
  and MAC policy itself are not.**
* **Hardlink and mount awareness**, device-node semantics, sparse-file layout, and file contents on
  other mounts (`one_file_system = true` by default).
* **Package-manager legitimacy.** FIM cannot tell a malicious change from a patch; use
  `rpm -Va`/`debsums` and your change process, and update the baseline through the audited command.
* **Resilience against weak hashes**: SHA-256 is used; no MD5/SHA-1.

## Baseline trust assumptions

1. The baseline is only as trustworthy as the system state when it was created. Create it from a
   known-good state (fresh install, verified packages).
2. Local self-hash = corruption detection. Signature = tamper detection **if the key is elsewhere**.
3. Keeping the baseline directory outside monitored roots protects it from being swept up in a
   restore or an unrelated change; it does **not** protect it from root.
4. Baseline version files are immutable; rollback is detected only via the audit chain, which a
   local root can rewrite. Off-host copies defeat this.

## Signing keys

* Generate with `fim keygen` **on an admin workstation or HSM-backed host**, not on the monitored
  server. Encrypt with `FIM_KEY_PASSPHRASE`. Never commit keys (`.gitignore` blocks `*.pem`/`*.key`;
  CI runs secret scanning).
* Keep only the **public** key on the monitored host.
* If the signing key is on the same host as an attacker with root, signatures add nothing against
  that attacker.
* Rotation and revocation: [user-guide.md](user-guide.md#signing-and-key-management).

## Recommended stronger deployment

1. **Forward alerts off-host in real time** (`[export.syslog]` over TCP/TLS-terminating forwarder to a
   write-once SIEM). Events then survive local tampering.
2. **Store baselines independently**: copy each signed `baseline-N.json(.sig)` and `audit.jsonl` to a
   separate, access-controlled system (object storage with versioning/object-lock, or a read-only
   share) immediately after each authorized update; compare periodically.
3. **Sign and verify from a separate trust domain** (admin workstation / CI); keep the private key
   offline.
4. **Run scans from outside when possible**: mount snapshots read-only on a hardened scanner, or
   scan from a rescue/initramfs environment for high-value hosts.
5. Combine with package verification, immutable infrastructure/rebuilds, auditd and EDR.

## Filesystem watcher limitations

* inotify (via `watchdog`) is best-effort: queue overflow drops events, directory-creation races
  can miss early child events, watch counts are limited, network/FUSE filesystems may emit nothing,
  and the process must be running. The watcher is therefore a **latency optimization**; the periodic
  full scan inside `fim watch` and the `fim-scan.timer` are authoritative.
* The watcher never updates the baseline and suppresses only *identical* repeat evidence.
* If an attacker kills the watcher, you get silence; monitor the service itself.

## What has been validated

Beyond the unit/integration suite on Ubuntu 24.04 / Python 3.13 / ext4 as root, the following were
actually executed during development (commands and numbers in the [README](../README.md#test-results)):

| Area | Evidence |
|---|---|
| Python 3.11, 3.12, 3.13 | Full suite passes (240 tests) locally; GitHub Actions matrix ran on all three |
| Non-root operation | Full suite as an unprivileged user (the real `chmod 000` test runs); a user with *only* `CAP_DAC_READ_SEARCH` can baseline and scan root-only files, and without it gets an INCOMPLETE scan |
| Distribution userlands with **their own packaged Python** | Ubuntu 24.04 (Python 3.12), Ubuntu 22.04 (installer correctly refuses system Python 3.10; works with the archive's `python3.11` release candidate), **Oracle Linux 9.8** (RHEL-compatible; `dnf install python3.11`): install, demo, uninstall, full suite as root and non-root. GitHub Actions also ran the Ubuntu and **Rocky Linux 9** install smoke jobs successfully |
| Debian 12 and Rocky 9 userlands with a standalone Python 3.11 | install, demo, uninstall and full suite (their package mirrors are unreachable from the sandbox) |
| Filesystems | ext4, tmpfs, overlayfs and **XFS** (loop-mounted): full suite passes; `user.*` xattrs verified on each |
| **Booted systemd 255** (privileged container) | `fim-scan.service` ran under its full hardening (`ProtectSystem=strict`, bounded capabilities, syscall filter): clean scan exits 0, a tampered file makes the unit `failed` with exit 1, reports are `0600` in a `0700` directory, mode-000 files and directories are still read, `fim-scan.timer` is scheduled, `fim-watch.service` reports a live modification. `systemd-analyze security`: exposure 3.1 (OK) |
| Syslog | Real `rsyslogd`: RFC 5424 over UDP and TCP parsed correctly (program, msgid, structured data); unix-socket delivery uses BSD framing after this was found necessary |
| inotify exhaustion | Real kernel limit lowered to 10 watches: `fim watch` exits 6 with an actionable message |
| Scale | 300,001 files + 512 MiB file: baseline 19.6 s, scan 14.1 s, ~590 MiB peak ([sizing](user-guide.md#sizing-and-performance)) |
| Extended attributes | `user.*` on ext4/tmpfs/overlayfs/XFS; a real `security.capability` was detected as `critical` (as root) |
| Backup and restore | tar round-trip, lost permissions, and old-pointer rollback all behave as documented |
| GitHub Actions | `fim-ci` ran on GitHub: lint/types, pip-audit, gitleaks, lockfile/schema reproducibility, Ubuntu and Rocky 9 smoke tests passed; it also caught a same-second report-name collision in `run-scan.sh`, now fixed |

## Platform-specific validation still required

Still **not** exercised; validate on real targets before relying on them:

- [ ] **SELinux enforcing** (label `/var/lib/fim` and `/opt/fim`, check for AVC denials) and
      **AppArmor** profiles. The sandbox kernel has neither enabled.
- [ ] **btrfs, ZFS and NFS** (this kernel has no btrfs; inode stability, mtime granularity and xattr
      semantics differ on network filesystems).
- [ ] Debian 12 / Rocky 9 **with their distribution Python packages on a real host** (their mirrors
      were unreachable from the sandbox; Oracle Linux 9 and Rocky 9 in GitHub Actions cover the
      RHEL family, Ubuntu covers the Debian family).
- [ ] Estates beyond ~300k files: memory is ~2 KiB/entry; validate `max_files`, `timeout_seconds` and
      `MemoryMax=` on your hardware.
- [ ] `fim watch` under heavy churn and across NFS/FUSE.
- [ ] Your SIEM's parsers for `fim@32473` and the CEF field mappings (rsyslog parsing was verified,
      your collector was not), including TLS-terminating forwarders.
- [ ] Hardware-backed key storage workflows (FIM only reads PEM files).

## Reporting vulnerabilities

See [../SECURITY.md](../SECURITY.md). The design analysis is in [threat-model.md](threat-model.md).
