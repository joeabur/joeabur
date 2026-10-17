# Changelog

All notable changes. Versioning: the report and baseline formats carry `schema_version`; a change
that older readers cannot parse bumps it.

## 0.1.0 (unreleased)

### Added
- Scanner, streaming SHA-256, versioned atomic baselines with hash-chained audit trail, optional
  Ed25519 detached signatures, severity policy, JSON/CSV/text/RFC 5424/CEF exports, optional
  inotify watcher with periodic full scans, hardened systemd units, Bash install/demo/scan helpers.
- Extended attribute tracking (POSIX ACLs, SELinux labels, file capabilities): `xattr_changed`,
  `scan.xattrs`, `file_capability_set` risk flag. Baselines without xattrs are still accepted.
- `scripts/benchmark.py`; executable documentation tests; GitHub Actions CI with SHA-pinned actions.

### Fixed (found by testing on real platforms and CI)
- Newly excluded directories were reported as deleted.
- `BaselineStore.load()` skipped the baseline-directory permission check.
- Unix-socket syslog needs BSD framing (rsyslog `imuxsock` does not parse RFC 5424 locally).
- `fim watch` crashed with a traceback when inotify limits were exhausted; now exits 6 with guidance.
- `fim watch` kept alerting on already-accepted changes after an authorized baseline update; it now
  adopts a newer trusted baseline.
- A configured root that is a symlink was recorded as a link and nothing beneath it was monitored.
- `run-scan.sh` report names could collide within one second; now unique per run.
- CEF output carried a dangling `cs2Label` when there were no risk flags.
- Export refusal (`already exists`) could leave a partial set of report files.

### Changed
- `FileRecord` is a slotted pydantic dataclass: peak memory at 300k files 1.16 GiB -> 590 MiB.
- systemd `MemoryMax` 1G -> 4G (sized from measurements).
