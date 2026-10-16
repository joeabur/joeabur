# Walkthrough: from `git clone` to cleanup

This tutorial takes you from a fresh clone to a verified, exported and cleaned-up FIM run. It uses
**only a temporary directory that you create**; it never scans or modifies system paths and it
needs no root privileges.

> **Illustrative vs. actual output.** Every command block marked as executable in this file is run
> by the automated test-suite (`tests/integration/test_docs.py`), and each "Expected output" block
> is compared to the *real* output after volatile values (temp-directory suffix, scan IDs,
> timestamps, hashes, host name, user) are masked. Those masked values will differ on your machine;
> everything else should match. Output shown for steps that are **not** executed by the tests
> (installation, below) is illustrative only.

Time: ~20 minutes. Prerequisites: Linux, Bash, Python ≥ 3.11 with `venv`, Git, internet access for
the install step. See [getting-started.md](getting-started.md) for distro-specific packages.

## Part 0: clone and install

```bash
git clone https://github.com/joeabur/joeabur.git
cd joeabur/file-integrity-monitor
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock   # pinned, hash-checked dependencies
.venv/bin/pip install --no-deps -e .
source .venv/bin/activate
fim version
```

Expected (illustrative; the version number moves with releases):

```text
fim 0.1.0
```

The remaining parts assume `fim` is on your `PATH` (the venv is activated) and that your current
directory is `file-integrity-monitor/` (the commands reference `config/fim.tutorial.toml.in`).

## Part 1: workspace and configuration

Create a throw-away workspace. `mktemp -d` guarantees a fresh, private directory, and the
baseline store (`state/`) sits **next to**, not inside, the monitored directory (`target/`):

<!-- fim-test:run -->
```bash
export WORK="$(mktemp -d /tmp/fim-tutorial.XXXXXX)"
mkdir -p "$WORK/target" "$WORK/state" "$WORK/reports"
chmod 700 "$WORK/state"
sed "s#@WORK@#$WORK#g" config/fim.tutorial.toml.in > "$WORK/fim.toml"
export FIM_CONFIG="$WORK/fim.toml"
fim config check
```

Expected output (illustrative: your temp suffix differs):

<!-- fim-test:expect -->
```text
configuration OK: /tmp/fim-tutorial.AbC123/fim.toml
  roots: /tmp/fim-tutorial.AbC123/target
  baseline.dir: /tmp/fim-tutorial.AbC123/state/baselines
  symlinks: record  exclusions: 0
  signature verification: off
```

`FIM_CONFIG` tells every `fim` command which configuration to use; the default would be
`/etc/fim/fim.toml`. All options are described in [configuration.md](configuration.md).

## Exercise 1: create and verify a baseline for a temporary test directory

Create four synthetic files, record the baseline, then scan:

<!-- fim-test:run -->
```bash
mkdir -p "$WORK/target/conf" "$WORK/target/bin" "$WORK/target/cache"
printf 'listen_port=8080\n' > "$WORK/target/conf/app.conf"
printf 'alice\nbob\n' > "$WORK/target/conf/users.txt"
printf '#!/bin/sh\necho hi\n' > "$WORK/target/bin/run.sh"; chmod 755 "$WORK/target/bin/run.sh"
printf 'cache-1\n' > "$WORK/target/cache/tmp.dat"
fim baseline create --reason "tutorial baseline"
fim scan; echo "exit code: $?"
```

<!-- fim-test:expect -->
```text
baseline v1 written to /tmp/fim-tutorial.AbC123/state/baselines/baseline-000001.json
  entries: 8  hashed bytes: 53
  complete: true  signed: false
FIM scan 0123456789ab  baseline v1  host=myhost
Roots: /tmp/fim-tutorial.AbC123/target
Scan mode: full
Scan status: COMPLETE
Entries scanned: 8  Bytes hashed: 53
Events: 0  (alert threshold: medium)

Result: CLEAN
exit code: 0
```

Why 8 entries? The baseline records 4 files **and** 4 directories (`target`, `bin`, `cache`,
`conf`), because directory permission/ownership changes matter too. The `warning: baseline is not
signed` line on stderr is expected until Exercise 3 (bonus).

Inspect what was recorded and check integrity yourself:

<!-- fim-test:run -->
```bash
fim baseline show
fim baseline verify
sha256sum "$WORK/target/conf/app.conf"
python3 - <<'PY'
import json, os
b = json.load(open(os.path.expandvars("$WORK/state/baselines/baseline-000001.json")))
for path, rec in sorted(b["entries"].items()):
    print(rec["type"], rec["mode"], rec["size"], (rec["sha256"] or "-")[:12], path.replace(os.environ["WORK"], "$WORK"))
PY
```

<!-- fim-test:expect -->
```text
version: 1
complete: true
entries: 8
prev_sha256: None
baseline v1: integrity OK (sha256 0123456789abcdef…)
signature: not configured
audit trail: 1 record(s), hash chain OK
dir 0755 4096 - $WORK/target
dir 0755 4096 - $WORK/target/bin
file 0755 18 299001868fb8 $WORK/target/bin/run.sh
file 0644 17 c9390b6f98ab $WORK/target/conf/app.conf
file 0644 10 464165db627e $WORK/target/conf/users.txt
```

**Success check:** `exit code: 0`, `Result: CLEAN`, and the first 12 hex digits printed by Python
for `app.conf` equal the start of the `sha256sum` line printed just above them. (Directory sizes,
like `4096`, depend on your filesystem.)

## Exercise 2: add, modify and delete files, then identify the findings

Simulate an incident: drop a hidden file, change a config, remove a file, and make a script
world-writable:

<!-- fim-test:run -->
```bash
printf 'backdoor\n' > "$WORK/target/bin/.hidden.sh"
printf 'listen_port=9999\n' > "$WORK/target/conf/app.conf"
rm "$WORK/target/conf/users.txt"
chmod 777 "$WORK/target/bin/run.sh"
fim scan --json "$WORK/reports/ex2.json"; echo "exit code: $?"
```

<!-- fim-test:expect -->
```text
Scan status: COMPLETE
Events: 4  (alert threshold: medium)

  SEVERITY  EVENT               PATH
  high      permission_changed  /tmp/fim-tutorial.AbC123/target/bin/run.sh  [mode] risk=world_writable
  high      modified            /tmp/fim-tutorial.AbC123/target/conf/app.conf  [sha256]
  high      deleted             /tmp/fim-tutorial.AbC123/target/conf/users.txt
  medium    added               /tmp/fim-tutorial.AbC123/target/bin/.hidden.sh

Result: ALERT
exit code: 1
```

Interpretation:

| Finding | Why |
|---|---|
| `permission_changed … [mode] risk=world_writable` | `run.sh` went `0755 → 0777`. *Newly* world-writable files are flagged. |
| `modified … [sha256]` | `app.conf` content hash differs. Same length (17 bytes), so only the hash revealed it. |
| `deleted` | `users.txt` is in the baseline but gone. |
| `added` | `.hidden.sh` was not in the baseline. |
| exit code `1` | At least one event is at or above `alert_threshold`. |

Now read the structured evidence from the JSON report:

<!-- fim-test:run -->
```bash
python3 - <<'PY'
import json, os
r = json.load(open(os.path.expandvars("$WORK/reports/ex2.json")))
print("complete:", r["summary"]["complete"], "alert:", r["summary"]["alert"], "events:", r["summary"]["event_count"])
for e in r["events"]:
    print(e["severity"], e["event_type"], os.path.basename(e["path"]), [c["field"] for c in e["changes"]], e["risk_flags"])
PY
```

<!-- fim-test:expect -->
```text
complete: True alert: True events: 4
high permission_changed run.sh ['mode'] ['world_writable']
high modified app.conf ['sha256'] []
high deleted users.txt [] []
medium added .hidden.sh [] []
```

### Event fields

| Field | Meaning |
|---|---|
| `timestamp`, `scan_id` | When the comparison ran and a random ID tying all events of one scan together. |
| `event_type` | `added`, `modified` (size/hash), `deleted`, `permission_changed`, `owner_changed`, `type_changed`, `symlink_changed`, `metadata_changed` (mtime only; content identical). |
| `path` | Absolute path. |
| `severity`, `rule` | Result of the [policy](configuration.md#policy): `info`/`low`/`medium`/`high`/`critical`, and which rule produced it (`default:<event>` or your rule name; `+risk` means setuid/setgid/world-writable escalation). |
| `baseline_version` | Which baseline it was compared against. |
| `changes[]` | Per-field `old` → `new` (`sha256`, `size`, `mode`, `uid`, `gid`, `link_target`, `type`, `mtime_ns`). |
| `before` / `after` | Full metadata record before (baseline) and after (now); `null` for added/deleted. |
| `risk_flags` | `setuid_set`, `setgid_set`, `world_writable`: newly risky bits. |

The complete schema is [schemas/report.schema.json](schemas/report.schema.json).

## Exercise 3: exclusions, baseline integrity, an authorized update, and exports

### 3a. Exclude a volatile directory

`cache/` churns constantly. Add an exclusion and modify the cache file:

<!-- fim-test:run -->
```bash
sed -i "s#^exclude = \[\]#exclude = [\"$WORK/target/cache/**\"]#" "$WORK/fim.toml"
fim config check
printf 'cache-2 (churn)\n' >> "$WORK/target/cache/tmp.dat"
fim scan -q --json "$WORK/reports/ex3-before.json"; echo "exit code: $?"
```

<!-- fim-test:expect -->
```text
  symlinks: record  exclusions: 1
warning: scan configuration (roots/exclude/symlinks) differs from the one used to build the baseline; run an authorized 'fim baseline update' if the change is intended
exit code: 1
```

The cache change is **not** reported, but the earlier Exercise 2 changes still are (exit 1), and
FIM warns that your configuration drifted from the one the baseline was built with: a changed
exclusion list silently changes what is verified, so you are told.

### 3b. Verify baseline integrity, and see what corruption looks like

<!-- fim-test:run -->
```bash
fim baseline verify
cp "$WORK/state/baselines/baseline-000001.json" "$WORK/baseline-1.backup"
sed -i '0,/"mode": "0755"/s//"mode": "0700"/' "$WORK/state/baselines/baseline-000001.json"
fim baseline verify; echo "exit code: $?"
cp "$WORK/baseline-1.backup" "$WORK/state/baselines/baseline-000001.json"
chmod 600 "$WORK/state/baselines/baseline-000001.json"
fim baseline verify
```

<!-- fim-test:expect -->
```text
baseline v1: integrity OK (sha256 0123456789abcdef…)
error: baseline baseline-000001.json failed its integrity check (content hash mismatch): it was modified or corrupted after it was written
the baseline is NOT trusted; see docs/troubleshooting.md
exit code: 4
baseline v1: integrity OK (sha256 0123456789abcdef…)
```

Exit code `4` means *do not trust any result*; scans refuse to run against such a baseline. (We
tampered with a **copy-protected** file here and restored it. A real attacker can also recompute
the embedded hash, which is why [signatures](#bonus-signed-baselines) exist; see
[security-and-limitations.md](security-and-limitations.md).)

### 3c. Perform an authorized baseline update

Accepting changes is a deliberate act: a `--reason` is mandatory, the current baseline must itself
verify, the diff is displayed first, and non-interactive use needs an explicit `--yes`. (Run
without `--yes` in a terminal and FIM asks you to type `yes`.)

<!-- fim-test:run -->
```bash
fim baseline update --reason "TUTORIAL-1: accept simulated changes and new exclusion" --yes
fim scan --json "$WORK/reports/final.json" --csv "$WORK/reports/final.csv"; echo "exit code: $?"
```

<!-- fim-test:expect -->
```text
Events: 4  (alert threshold: medium)
baseline updated: v1 -> v2
  signed: false  audit reason: TUTORIAL-1: accept simulated changes and new exclusion
FIM scan 0123456789ab  baseline v2  host=myhost
Events: 0  (alert threshold: medium)
Result: CLEAN
exit code: 0
```

### 3d. Export reports and read the audit trail

<!-- fim-test:run -->
```bash
printf 'new file after update\n' > "$WORK/target/conf/extra.conf"
fim scan --json "$WORK/reports/final2.json" --csv "$WORK/reports/final2.csv" -q; echo "exit code: $?"
fim report convert "$WORK/reports/final2.json" --format cef
head -n 1 "$WORK/reports/final2.csv" | cut -d, -f1-9
fim audit show
fim audit verify
stat -c '%a %n' "$WORK"/reports/* | sed "s#$WORK/##"
```

<!-- fim-test:expect -->
```text
exit code: 1
CEF:0|FIM|fim|0.1.0|added|File added|5|rt=1792193396000 dvchost=myhost externalId=0123456789ab filePath=/tmp/fim-tutorial.AbC123/target/conf/extra.conf fileHash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fsize=22 filePermission=0644 cs1Label=rule cs1=default:added
timestamp,scan_id,severity,event_type,path,rule,baseline_version,changed_fields,old_sha256
#1 2026-10-16T23:29:53+00:00 create  v1 user=root(uid 0) reason='tutorial baseline'
#2 2026-10-16T23:29:56+00:00 update  v2 user=root(uid 0) reason='TUTORIAL-1: accept simulated changes and new exclusion'
audit trail OK: 2 record(s)
600 reports/ex2.json
600 reports/final.csv
600 reports/final.issues.csv
600 reports/final2.json
```

(`rt=` is the event time in epoch milliseconds; the test masks it, so your value differs.)

**Success check for the whole exercise:** exports exist with mode `600`; `audit show` lists
your `create` and `update` with the reasons you typed; `audit verify` reports OK; every `*.csv`
has a sibling `*.issues.csv`.

## Bonus: signed baselines

Detached Ed25519 signatures let you detect a baseline that was edited *and* re-hashed. The private
key must live somewhere an attacker on the monitored host cannot reach. Here we keep it inside the
tutorial workspace purely for demonstration, and **you must not do this in production**.

<!-- fim-test:run -->
```bash
mkdir "$WORK/keys"
fim keygen --private "$WORK/keys/fim.key" --public "$WORK/keys/fim.pub"
printf 'public_key = "%s/keys/fim.pub"\n' "$WORK" > "$WORK/pk.line"
sed -i "/^dir = /r $WORK/pk.line" "$WORK/fim.toml"
fim scan; echo "exit code: $?"
fim sign --key "$WORK/keys/fim.key" --reason "TUTORIAL-2: start signing"
fim baseline verify
fim scan; echo "exit code: $?"
```

<!-- fim-test:expect -->
```text
Move the private key off this host (or into an HSM/offline store); never commit it.
error: baseline-000002.json.sig is missing but a public key is configured: refusing unsigned baseline
exit code: 4
signature: verified (sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
audit trail: 3 record(s), hash chain OK
  medium    added               /tmp/fim-tutorial.AbC123/target/conf/extra.conf
exit code: 1
```

Once a public key is configured an *unsigned* baseline is rejected (exit 4), which is exactly what
stops an attacker from simply deleting the `.sig` file. The final `exit code: 1` is the
`extra.conf` file added in step 3d.

## Cleanup

Everything lives under `$WORK`. The guard below only deletes a path that matches the pattern
`mktemp` produced:

<!-- fim-test:run -->
```bash
case "$WORK" in
  /tmp/fim-tutorial.*) rm -rf -- "$WORK" ;;
  *) echo "refusing to delete unexpected path: $WORK" ;;
esac
unset WORK FIM_CONFIG
ls -d /tmp/fim-tutorial.* 2>/dev/null || echo "workspace removed"
```

<!-- fim-test:expect -->
```text
workspace removed
```

To also remove the install: `deactivate && rm -rf .venv` (or `scripts/uninstall.sh` for a system
install). Nothing outside `$WORK` and `.venv` was created.

## Where next

* All commands: [user-guide.md](user-guide.md#command-reference)
* Putting it into production (systemd timer, syslog/SIEM): [user-guide.md](user-guide.md#running-in-production)
* What FIM cannot protect against: [security-and-limitations.md](security-and-limitations.md)
* Something failed: [troubleshooting.md](troubleshooting.md)
