# Configuration reference

FIM reads one TOML file: `--config/-c PATH`, else `$FIM_CONFIG`, else `/etc/fim/fim.toml`. Unknown
keys, wrong types, relative paths and paths containing `..` are **rejected** with a message
naming the key. Validate with `fim config check`. A full, commented example is
[config/fim.example.toml](../config/fim.example.toml); the smallest valid file is
[config/fim.minimal.toml](../config/fim.minimal.toml).

```toml
[baseline]
dir = "/var/lib/fim/baselines"

[scan]
roots = ["/etc"]
```

## `[baseline]`

| Key | Default | Meaning |
|---|---|---|
| `dir` | required | Baseline store. Absolute; **must not overlap any scan root** (checked after resolving symlinks). Created `0700` on first baseline; later runs refuse it if it is a symlink, owned by someone else, or group/world accessible. |
| `keep_versions` | `10` | Old baseline versions retained (2-1000). The current version is never pruned. |
| `public_key` | unset | Path to the Ed25519 **public** key. When set, every load requires a valid detached signature; an unsigned or mis-signed baseline is rejected (exit 4). Must not be inside `dir`. |
| `max_baseline_bytes` | `536870912` | Refuse to load larger baseline files (memory guard). |

## `[scan]`

| Key | Default | Meaning |
|---|---|---|
| `roots` | required | Files or directories to monitor (absolute, de-duplicated). A root that is itself a symlink (e.g. `/bin` → `usr/bin`) is followed, because you named it explicitly; symlinks *below* a root follow the `symlinks` policy. |
| `exclude` | `[]` | Absolute globs for volatile paths. `*`/`?` stay within one path segment; `**` crosses `/` (`**/` may match nothing). A directory matched by `PATTERN` or `PATTERN/` is pruned. |
| `symlinks` | `record` | `record`: store the link and its target, never follow. `skip`: ignore links. `follow`: follow links that stay inside the roots and hash the target; symlink loops are detected (`symlink_loop`). |
| `follow_outside_roots` | `false` | Only with `follow`: also follow links leading outside the roots. Off by default; otherwise reported as informational `symlink_outside_root`. |
| `xattrs` | `true` | Record extended attributes (POSIX ACLs `system.posix_acl_*`, SELinux label `security.selinux`, file capabilities `security.capability`, `user.*`). Only a SHA-256 of each value is stored, never the value. Filesystems without xattr support yield "not collected" and never alert; a baseline made without xattrs (older version, or `xattrs = false`) never alerts on them either. A real read failure (e.g. `EACCES`) is an `unreadable` issue. |
| `one_file_system` | `true` | Do not descend into other mounts (keeps `/proc`, `/sys`, network mounts out). |
| `max_files` | `2000000` | **Memory scales with entries (~2 KiB each, measured; see [sizing](user-guide.md#sizing-and-performance)).** Abort after this many entries; scan becomes incomplete (`limit_reached`) and **no deletions are reported**. |
| `max_file_bytes` | `1073741824` | Larger files are *not hashed* and are reported as `too_large` (incomplete); `0` = unlimited. |
| `max_depth` | `64` | Directory depth limit (`max_depth` issue beyond it). |
| `timeout_seconds` | `3600` | Wall-clock limit (`0` = none); aborts like `max_files`. |
| `chunk_size` | `1048576` | Streaming read size for hashing (4 KiB-64 MiB). Memory use is independent of file size. |

## `[policy]`

`alert_threshold` (default `medium`): the lowest severity that sets `alert = true` and makes
`fim scan` exit `1`.

Severities: `info < low < medium < high < critical`.

Event types and default severities: `added` medium, `modified` high, `deleted` high,
`permission_changed` high, `owner_changed` high, `type_changed` high, `symlink_changed` high,
`xattr_changed` high (ACL/label/capability/user attribute added, removed or changed), `metadata_changed` info (mtime changed, content identical).

Override per type:

```toml
[policy.severities]
added = "low"
```

Per-path rules, **first match wins** (put specific rules first):

```toml
[[policy.rules]]
name = "ssh-config"
paths = ["/etc/ssh/**"]
events = ["modified", "added", "deleted"]   # optional; default = all events
severity = "critical"
```

Escalation on top of any rule: a newly set **setuid/setgid** bit or a new/changed **file capability** (`file_capability_set`) raises to `critical`; a newly
**world-writable** mode raises to at least `high` (event `rule` gets a `+risk` suffix and
`risk_flags` lists why).

## `[export.syslog]`

Used by `fim scan --syslog` and `fim watch --syslog`.

| Key | Default | Meaning |
|---|---|---|
| `address` | `/dev/log` | Unix socket path, `udp://host:port` or `tcp://host:port` (TCP uses RFC 6587 octet-counting). |
| `format` | `rfc5424` | `rfc5424` (structured data id `fim@32473`; replace 32473, the RFC 5612 documentation number, with your organisation's IANA PEN before production use) or `cef`. |
| `facility` | `13` | Syslog facility 0-23 (13 = log audit). |
| `app_name` | `fim` | RFC 5424 APP-NAME. |
| `min_severity` | `low` | Events below this are not sent. |

Framing depends on `address`: **UDP/TCP** carry RFC 5424 (or CEF). A **unix socket** (such as `/dev/log`) receives BSD syslog framing (`<PRI>Mmm dd hh:mm:ss app: key="value" …`), because local daemons (rsyslog `imuxsock`, syslog-ng, journald) do not parse RFC 5424 on local sockets; verified against rsyslog (see [security-and-limitations.md](security-and-limitations.md#what-has-been-validated)). CEF is sent unchanged on every transport.

Severity mapping: RFC 5424 info→6, low→5, medium→4, high→3, critical→2. CEF severity 1/3/5/8/10.
An incomplete scan additionally emits one `scan_incomplete` message. If delivery fails, `fim`
reports it on stderr and exits `5` (unless a more important code applies).
Field-by-field formats are in [user-guide.md](user-guide.md#siem-and-syslog-export).

## `[watch]`

| Key | Default | Meaning |
|---|---|---|
| `debounce_seconds` | `1.0` | Collect events this long before re-inspecting changed paths. |
| `full_scan_interval_seconds` | `3600` | Authoritative periodic full scan while watching (`0` disables; not recommended). |

## Environment variables

| Variable | Used by |
|---|---|
| `FIM_CONFIG` | default config path |
| `FIM_KEY_PASSPHRASE` | encrypts the private key in `fim keygen`, decrypts it in `sign`/`--sign-key`. Never passed on the command line. |
| `FIM_BIN`, `REPORT_DIR`, `REPORT_RETENTION_DAYS`, `FIM_SYSLOG` | `scripts/run-scan.sh` |
| `FIM_PYTHON` | `scripts/install.sh` interpreter |

## Validation examples

| Mistake | Message |
|---|---|
| `dir = "baselines"` | `baseline.dir: Value error, baseline.dir must be absolute` |
| `roots = ["/etc/../root"]` | `... must not contain '..' segments` |
| `dir` inside a root | `baseline.dir ... overlaps monitored root ...; store baselines outside monitored directories` |
| typo `symlink = "record"` | `scan.symlink: Extra inputs are not permitted` |
