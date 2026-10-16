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
  is not detected: **ACLs, extended attributes, SELinux contexts, file capabilities and
  immutable flags are not recorded.**
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

## Platform-specific validation still required

The development environment was Ubuntu 24.04 (containerized, running as root). The following were
**not** exercised and need validation on real targets before you rely on them:

- [ ] Run `scripts/install.sh` and `scripts/demo.sh` on **RHEL 9 / Rocky 9 / Alma 9** with
      Python 3.11/3.12 (CI job `install-smoke-rhel` exists; confirm it passes).
- [ ] Debian 12 and Ubuntu 22.04 (Python 3.11/3.10 is below the minimum on 22.04: use deadsnakes or
      a newer interpreter).
- [ ] The systemd units on a booted host: `systemd-analyze security fim-scan.service`, timer firing,
      `ProtectSystem=strict` with your `report_dir`, capability set sufficient to read all monitored
      paths, `SystemCallFilter` compatible with your Python build.
- [ ] **SELinux enforcing** (RHEL family): label `/var/lib/fim` and `/opt/fim`, confirm no AVC denials.
- [ ] **AppArmor** profiles on Ubuntu/Debian if you confine the service.
- [ ] Non-root operation with only `CAP_DAC_READ_SEARCH`/`CAP_FOWNER` (the test-suite ran as root, so
      real `chmod 000` behavior is covered only by injected `PermissionError` tests).
- [ ] Filesystems: XFS, btrfs, ZFS, NFS, overlayfs (inode stability, mtime granularity, `O_NOATIME`).
- [ ] Large-scale performance: millions of files, baseline memory (the baseline is held in memory
      as JSON; `max_baseline_bytes` guards it), and scan time vs `timeout_seconds`.
- [ ] inotify limits and behavior under heavy churn; `fim watch` under systemd.
- [ ] Syslog delivery to your real collector (rsyslog/syslog-ng/SIEM parsers for `fim@32473` and CEF
      field mappings), including TLS-terminating forwarders.
- [ ] Hardware-backed key storage workflow (HSM/YubiKey) if required: FIM only reads PEM files.
- [ ] Backup/restore of the baseline directory preserving `0700/0600`.

## Reporting vulnerabilities

See [../SECURITY.md](../SECURITY.md). The design analysis is in [threat-model.md](threat-model.md).
