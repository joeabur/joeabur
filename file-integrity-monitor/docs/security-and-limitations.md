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
actually executed during development (details and commands in the [README](../README.md#test-results)):

| Area | Evidence |
|---|---|
| Python 3.11 and 3.12 | Full suite passes (236 tests) |
| Non-root operation | Full suite as an unprivileged user (real `chmod 000` unreadable-file test runs); a non-root user with *only* `CAP_DAC_READ_SEARCH` (via `setpriv` ambient caps) can baseline and scan root-only files, and without the capability gets an INCOMPLETE scan |
| Debian 12 and Rocky Linux 9 userlands | `scripts/install.sh` (hash-pinned), `scripts/demo.sh`, `scripts/uninstall.sh` and the full test suite, as root and non-root, on overlayfs (Python 3.11.15 standalone build, because the distro package mirrors were unreachable from the sandbox) |
| tmpfs and overlayfs | Full suite passes |
| systemd units | `systemd-analyze verify` and `systemd-analyze security --offline`: exposure 3.1 ("OK"). Not started under a booted systemd |
| Syslog | Real `rsyslogd`: RFC 5424 over UDP and TCP parsed correctly (program, msgid, structured data); unix-socket delivery uses BSD framing after this was found necessary |
| inotify exhaustion | Real kernel limit lowered to 10 watches: `fim watch` exits 6 with an actionable message |
| Scale | 300,001 files + 512 MiB file benchmark ([sizing](user-guide.md#sizing-and-performance)) |
| Extended attributes | `user.*` xattrs on ext4/tmpfs/overlayfs; a real `security.capability` set on a file was detected as `critical` (as root) |

## Platform-specific validation still required

Still **not** exercised; validate on real targets before relying on them:

- [ ] Rocky/RHEL/Debian **with the distribution's own Python package** (`dnf install python3.11` /
      `apt install python3-venv`): the sandbox blocked those mirrors; CI job `install-smoke-rhel` covers it
      once it has run on GitHub.
- [ ] Ubuntu 22.04 (system Python 3.10 is below the 3.11 minimum: use a newer interpreter).
- [ ] The systemd units on a **booted** host: timer firing, `ProtectSystem=strict` with your report
      directory, the capability set reading *all* of your monitored paths, `SystemCallFilter` with your
      Python build, `MemoryMax=` against your estate size.
- [ ] **SELinux enforcing** (label `/var/lib/fim` and `/opt/fim`, check for AVC denials) and
      **AppArmor** profiles.
- [ ] XFS, btrfs, ZFS, NFS (inode stability, mtime granularity, `O_NOATIME`, xattr semantics).
- [ ] Estates beyond ~300k files: memory is ~4 KiB/entry (an optimization opportunity); validate
      `max_files`, `timeout_seconds` and `MemoryMax=` on your hardware.
- [ ] `fim watch` under systemd with heavy churn, and across NFS/FUSE.
- [ ] Your SIEM's parsers for `fim@32473` and the CEF field mappings (rsyslog parsing was verified,
      your collector was not), including TLS-terminating forwarders.
- [ ] Hardware-backed key storage workflows (FIM only reads PEM files).
- [ ] Backup/restore of the baseline directory preserving `0700/0600`.

## Reporting vulnerabilities

See [../SECURITY.md](../SECURITY.md). The design analysis is in [threat-model.md](threat-model.md).
