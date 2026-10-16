# Troubleshooting

Always start with: `fim config check`, `fim baseline verify`, then `fim audit verify`.
Exit codes are listed in [user-guide.md](user-guide.md#exit-codes).

## Permissions

| Symptom | Cause / fix |
|---|---|
| `error: ... has unsafe permissions 0755; run: chmod 700 DIR` (exit 6) | The baseline directory is group/world accessible. `chmod 700 DIR`. If you did not change it, treat as a possible tamper attempt and run `fim baseline verify`. |
| `... is owned by uid N, not by the current user` | Baselines were created by another user (e.g. via `sudo`). Run `fim` as the same user every time (use `sudo fim` consistently, or `sudo -u fimuser`). |
| `... must be a real directory (not a symlink or file)` | `baseline.dir` is a symlink. Point the config at the real directory. |
| Scan is INCOMPLETE with many `unreadable` / `walk_error` | Not enough privilege. Run as root or grant `CAP_DAC_READ_SEARCH` (systemd: `AmbientCapabilities=` + `CapabilityBoundingSet=`). On SELinux-enforcing hosts, a confined service may also be denied; check `ausearch -m avc -ts recent`. |
| `refusing to overwrite ...` / `already exists; use --overwrite` | Deliberate protection for reports, keys and baseline versions. Choose a new name. |
| `private key ... is accessible by group/others; chmod 600 it` | Fix the key mode. |

## Missing dependencies

| Symptom | Fix |
|---|---|
| `Python >= 3.11 is required` (installer) | Debian/Ubuntu: `apt install python3 python3-venv`. RHEL 9: `dnf install python3.11`, then `FIM_PYTHON=python3.11 scripts/install.sh`. |
| `the venv/ensurepip module is missing` | `apt install python3-venv` (Debian family). |
| `signing needs the 'cryptography' package` | `pip install 'fim-tool[signing]'` (already in `requirements.lock`; reinstall without `--no-extras`). |
| `filesystem watching needs 'watchdog'` | `pip install 'fim-tool[watch]'`, or use the fallback: schedule `fim scan` with `systemd/fim-scan.timer` or cron. |
| `pip` reports `THESE PACKAGES DO NOT MATCH THE HASHES` | The download was corrupted or tampered with. Retry on a trusted network; never bypass `--require-hashes`. |
| `fim: command not found` | Activate the venv (`source .venv/bin/activate`) or call `.venv/bin/fim`; for system installs check `/usr/local/bin/fim`. |

## Filesystem watcher limitations

| Symptom | Explanation / fix |
|---|---|
| `OSError: inotify watch limit reached` / `inotify instance limit reached` | Raise `fs.inotify.max_user_watches` (e.g. `sysctl fs.inotify.max_user_watches=524288`) or monitor fewer directories. |
| Changes on NFS/SMB/FUSE are not reported | inotify only sees changes made through the local kernel. Rely on the periodic full scan (`watch.full_scan_interval_seconds`) or scan on the file server. |
| A burst of changes shows only some files | The event queue can overflow, and files created in a brand-new directory may be missed. The periodic full scan is the authority; keep it enabled. |
| `fim watch` prints nothing for a change you made | The path may be excluded, out of scope, or already reported with identical evidence (duplicates are suppressed). Run `fim scan --root PATH`. |
| Works in a container but not in CI | Some sandboxes have no inotify; the watcher integration tests skip themselves in that case. |

## Interrupted or failed scans

* **Ctrl-C / `kill` during `fim scan`:** nothing is written except optional report files; the
  baseline is untouched. Re-run.
* **Interrupted `baseline update/create`:** the new baseline is written to a temp file, fsynced,
  and atomically linked into place **before** the `CURRENT` pointer moves, so you keep the old
  baseline. An orphan `baseline-00000N.json` may remain; it is ignored and the next version
  number skips it. `rm` the orphan if you wish.
* **`another FIM operation holds .../.lock (waited 10s)`:** another `fim` is writing. Wait, or check
  `ps`/`lsof` on the lock file. The lock is released automatically when the process exits.
* **Exit 3 `INCOMPLETE`:** see the issue table in
  [user-guide.md](user-guide.md#interpreting-incomplete-scans). `limit_reached`/`timeout` mean the
  scan was *aborted*; raise limits or narrow roots.
* **`changed_during_hash` on log files or databases:** they are high-churn; exclude them.

## Signature verification failures (exit 4)

| Message | Meaning / action |
|---|---|
| `baseline-00000N.json.sig is missing but a public key is configured` | Unsigned baseline, or the `.sig` was removed. If you just enabled `public_key`, sign the current baseline: `fim sign --key KEY`. Otherwise treat as tampering. |
| `baseline signature does not match the baseline contents` | The baseline changed after signing (or the wrong `.sig`). Restore the baseline and signature from your independent copy; do **not** re-sign until you know why. |
| `signature was made by sha256:A, trusted key is sha256:B` | Wrong key or rotation in progress. Finish the [rotation procedure](user-guide.md#signing-and-key-management). |
| `signature file is malformed` / `not valid base64` | The `.sig` is damaged. |
| `cannot load public key` | `baseline.public_key` path wrong or not an Ed25519 PEM. |
| `signing key ... does not match baseline.public_key` | You passed a different private key than the trusted public key. |
| `signing key must not be stored inside the baseline directory` / `... a monitored root` | Move the private key elsewhere (ideally off-host). |

## Corrupted or suspicious baselines (exit 4)

| Message | Meaning / action |
|---|---|
| `failed its integrity check (content hash mismatch)` | The file was altered or damaged after writing. Restore from backup/remote copy. |
| `is corrupt or malformed` | Truncated or non-JSON file (disk full, interrupted copy). Restore from backup. |
| `claims to be version N` | A file was renamed or swapped. |
| `audit trail says the current baseline is vN ... possible rollback or tampering` | `CURRENT` points to a different baseline than the last audited write. Inspect `fim baseline list`, `fim audit show`. |
| `audit trail broken at record N` / `record N was modified` | `audit.jsonl` was edited, truncated or reordered. |
| `CURRENT pointer is corrupt` | Fix with `echo 000003 > CURRENT` **only** after `fim baseline verify --version 3` succeeds and the audit trail agrees. |

Recovery when there is no good copy: investigate first, then
`fim baseline create --force --reason "rebuild after INC-123"`. Old versions are never overwritten.
A recovered baseline is only as trustworthy as the host state at that moment; see
[security-and-limitations.md](security-and-limitations.md).

## Configuration errors (exit 2)

Messages name the offending key (`scan.roots: ... must be absolute`). Unknown keys are errors by
design: fix the typo. `baseline.dir ... overlaps monitored root` means the store is inside (or
contains) a monitored directory; move it, e.g. `/var/lib/fim`.

## Tests and tooling

* `pytest` fails with `OSError: inotify...` → watcher tests skip automatically in sandboxes; run
  `pytest -m "not watcher"` to deselect them.
* Permission-denied tests are skipped when running as root (root bypasses file modes); the same code
  paths are covered by injected `PermissionError` tests.
* `bats: command not found` → `apt install bats` / `npm i -g bats`; `shellcheck` →
  `apt install shellcheck` / `pip install shellcheck-py`.
