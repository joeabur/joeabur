# Getting started

FIM (File Integrity Monitor) records a trusted **baseline** of files (SHA-256 hash, size, owner,
mode, mtime, symlink target), then **scans** the filesystem and reports every difference as an
evidence-backed event. It is read-only with respect to monitored files: it never modifies or
restores them.

Not sure whether FIM fits? Read [security-and-limitations.md](security-and-limitations.md)
first: local hashing cannot protect you from an attacker who controls the host *and* your signing
key.

## Requirements

| Item | Requirement |
|---|---|
| OS | Linux. Designed for **Ubuntu 22.04/24.04, Debian 12** and **RHEL-compatible 9** (RHEL, Rocky, AlmaLinux, CentOS Stream, Fedora). Validation status per platform: see [Platform validation status](#platform-validation-status). |
| Python | CPython **3.11, 3.12 or 3.13** with the `venv` module |
| Runtime dependencies | `pydantic` and `typer` (always); `cryptography` (only for signing); `watchdog` (only for `fim watch`) |
| Filesystem | POSIX semantics. `O_NOATIME`, `inotify` and `flock` are used where available |
| Privileges | See below |

### Distribution packages

```bash
# Debian / Ubuntu
sudo apt-get install -y python3 python3-venv git
# RHEL 9 / Rocky / Alma (the default python3 is 3.9: install 3.11 or 3.12)
sudo dnf install -y python3.11 git
```

On RHEL-family systems run the installer with `FIM_PYTHON=python3.11 scripts/install.sh`.

### User and permission requirements

* **Learning / testing:** any unprivileged user, scanning a directory you own (this is what the
  [walkthrough](walkthrough.md) does).
* **Monitoring system paths** (`/etc`, `/boot`, `/usr/local/bin`): run as **root**, or as a
  dedicated user holding `CAP_DAC_READ_SEARCH` (read any file) and ideally `CAP_FOWNER`
  (lets FIM open files with `O_NOATIME` so scanning does not even alter access times; FIM falls
  back transparently without it). Files FIM cannot read are reported as `unreadable` and make the
  scan **incomplete**; they are never silently treated as clean.
* **Baseline directory:** owned by the user running `fim`, mode `0700`, a real directory (not a
  symlink), and **outside every monitored root**. FIM refuses to run otherwise.
* **Signing private key:** must *not* live on the monitored host (see
  [security-and-limitations.md](security-and-limitations.md#signing-keys)). FIM refuses a key whose
  file is group/world readable.

## Install

### Option A: local virtual environment (no root; used by the tutorial)

```bash
git clone https://github.com/joeabur/joeabur.git
cd joeabur/file-integrity-monitor
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock   # hash-pinned dependencies
.venv/bin/pip install --no-deps -e .
.venv/bin/fim version
```

### Option B: system install with the installer script

```bash
sudo scripts/install.sh --dry-run          # show exactly what would happen
sudo scripts/install.sh --with-systemd     # venv in /opt/fim, link in /usr/local/bin/fim
```

The installer: checks the Python version and `venv`; creates `/opt/fim` (marked with
`.fim-install`); installs the hash-pinned dependencies; links `fim`; installs
`/etc/fim/fim.toml` **only if absent**; creates `/var/lib/fim` (`0700`); with `--with-systemd`
copies the units (never enabling or starting them). Everything is overridable
(`--prefix`, `--bin-dir`, `--etc-dir`, `--state-dir`, `--systemd-dir`); run `scripts/install.sh --help`.
Uninstall with `scripts/uninstall.sh`, which only removes a prefix carrying its marker and never
touches configuration or baselines.

### Optional components

| Feature | Extra | Install |
|---|---|---|
| Detached baseline signatures | `signing` | included by `requirements.lock`; or `pip install 'fim-tool[signing]'` |
| Real-time monitoring | `watch` | included by `requirements.lock`; or `pip install 'fim-tool[watch]'` |

`scripts/install.sh --no-extras` installs only the two core dependencies.

## First run in 2 minutes

The fastest safe demo: the script creates its own temporary workspace, runs the full cycle and
deletes only what it created.

```bash
scripts/demo.sh
```

Then do the real thing step by step in the [walkthrough](walkthrough.md).

## Platform validation status

| Platform | Status in this repository |
|---|---|
| Ubuntu 24.04, Python 3.13 | Unit, integration, shell and documentation tests executed (see [README](../README.md#test-results)) |
| Python 3.11 and 3.12 | Full suite executed and passing; also in the CI matrix |
| Debian 12 and Rocky Linux 9 (containers, non-root and root) | Install, demo, uninstall and full test suite executed and passing, using a standalone Python 3.11 because distro package mirrors were unreachable; CI jobs use the distro packages |
| tmpfs, overlayfs | Full suite executed and passing |
| SELinux/AppArmor, booted systemd, XFS/btrfs/NFS, very large estates | Not validated; see [the checklist](security-and-limitations.md#platform-specific-validation-still-required) |

## Next steps

1. [walkthrough.md](walkthrough.md): hands-on tutorial with three exercises
2. [user-guide.md](user-guide.md): commands, workflows, production setup
3. [configuration.md](configuration.md): every option
4. [troubleshooting.md](troubleshooting.md) when something goes wrong
