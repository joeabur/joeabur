# Walkthrough: from fresh clone to a finished investigation

Everything in sections 1–13 and Exercises 2–4 uses **synthetic evidence**, needs **no root**, no production data and
no network access (except `pip install` once). Exercise 1 and the optional section run read-only collection on the
machine you are logged in to; use a test machine.

Output marked **(actual)** was produced by running the command during development. Output marked **(illustrative)**
shows the shape of results that will differ on your machine. Hashes, owners and timestamps in synthetic output can differ if
you regenerate the fixtures.

## 1. Supported distributions and prerequisites

Ubuntu 22.04/24.04, Debian 12, Fedora 40+ (systemd), x86-64/ARM64 are the targets; non-systemd Linux works with reduced
scope. You need `git`, Python 3.11+ (3.12 recommended) and `python3-venv`. Synthetic parts also work on macOS/Windows
(WSL) because they only parse files.

## 2. Clone

```bash
git clone <repository-url>
cd incident-response-toolkit/linux
```

## 3–4. Virtual environment and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -c requirements/constraints.txt -e ".[dev]"
```

(`./scripts/setup-dev.sh` does the same.) Deactivate later with `deactivate`.

## 5. Run the test suite

```bash
pytest -q
```

Expected (actual at time of writing; the count grows as tests are added): `146 passed` and no failures. The suite uses a
fake root filesystem and mocked commands; it does not need root.

## 6. Check platform readiness

```bash
python -m linux_ir doctor
```

Illustrative: lines such as `[OK  ] operating system: Linux (Ubuntu 24.04 LTS)`, `[WARN] tool:ss: not found (related
data will be partial)`. `WARN` means a source will be partial, not that anything is broken. `FAIL` (non-Linux) exits 1.

## 7. Dry-run collection

```bash
python -m linux_ir collect --dry-run --profile basic --output ./evidence
```

(actual, abridged)

```
DRY RUN: profile=basic; nothing will be collected or written. Output would go under ./evidence/<host>-<UTC time>-<id>/

[inventory] Host/OS metadata, uptime, sessions, mounts, disk space, selected security settings
  privileges: No privileges required.
  - read /etc/os-release, /proc/uptime, /proc/stat, /proc/self/mounts, /proc/1/comm
...
```

Verify nothing was created: `ls ./evidence` should fail with "No such file or directory".

## 8. Basic collection without root

Run as a normal user (the tool never uses sudo):

```bash
python -m linux_ir collect --profile basic --output ./evidence
```

(actual, from a root container without `ss`/`ip`; as a normal user expect more `permission_denied` errors)

```
Evidence collected: ./evidence/vm-20261016T082203Z-1a199c
Manifest SHA-256 (store a copy separately): d4cc65…eb008
  inventory    ok          records=9      errors=0
  logs         ok          records=1      errors=0
  network      partial     records=60     errors=5
  persistence  partial     records=30     errors=1
  processes    ok          records=77     errors=0
  files        skipped     records=0      errors=0
Some data is missing (see manifest errors). Missing data is NOT evidence of absence of activity. ...
EVIDENCE_DIR=./evidence/vm-20261016T082203Z-1a199c
```

Keep the directory in a variable for later steps:

```bash
EV=$(ls -d ./evidence/*/ | tail -1); echo "$EV"
```

## 9. Inspect the manifest

```bash
python -m json.tool "$EV/manifest.json" | head -60
```

Look at `started_at`/`finished_at` (UTC), `privileged`, `coverage` (which artifacts were `ok`, `partial`, `skipped`),
each artifact's `errors`, and `files` (path, size, SHA-256). `files` is what verification checks.

## 10. Verify SHA-256 hashes

```bash
python -m linux_ir verify-manifest --input "$EV"; echo "exit=$?"
```

(actual)

```
Manifest SHA-256: d4cc651cf777ed233f719ff5cb8127f5aa7e2bf9bdcc40814085b452588eb008
Verified files : 5
RESULT: PASS: all hashes match
exit=0
```

Write the manifest SHA-256 somewhere *outside* the evidence directory — see [evidence handling](evidence-handling.md).

## 11. Analyse synthetic process and persistence artifacts

```bash
CASE=examples/synthetic-evidence/case-001
python -m linux_ir verify-manifest --input $CASE
python -m linux_ir scan --input $CASE
```

(actual, abridged) – 16 heuristic findings, for example:

```
16 finding(s) from 24 rules
[HIGH    /medium] LIR-PERS-002 systemd unit executes from a world-writable staging directory
    Unit evil-updater.service (/etc/systemd/system/evil-updater.service) runs /tmp/.cache/kworker-upd from a staging directory.
    ref: artifacts/persistence.json#records[1]
[HIGH    /low   ] LIR-PERS-005 Cron entry contains analyst-defined suspicious pattern
...
note: LIR-PERS-003: no baseline supplied for 'persistence'; rule not evaluated
A finding is a lead, not a verdict. Missing coverage is not a clean result.
```

Each line shows **severity/confidence**, the stable rule ID, why it matched, and the evidence reference.

## 12. Match synthetic IOCs (and a baseline)

```bash
python -m linux_ir scan --input $CASE --iocs examples/iocs.json \
  --baseline examples/synthetic-evidence/baseline | grep -E "^\[.*(IOC-MATCH|PERS-003)"
```

You should see `IOC-MATCH-IP`, `-SHA256`, `-FILE_PATH`, `-PROCESS_NAME`, `-DOMAIN` entries and `LIR-PERS-003`
("New systemd unit compared with baseline"). 42 findings in total (actual). An IOC match means *equal to a supplied
indicator*; it is not a verdict.

## 13. Generate and review reports

```bash
python -m linux_ir report --input $CASE --iocs examples/iocs.json \
  --baseline examples/synthetic-evidence/baseline --output ./reports/synthetic
ls ./reports/synthetic
```

(actual)

```
evidence-manifest.json  evidence-manifest.sha256  executive-summary.md  findings.csv  report.json  technical-report.md
```

Open `executive-summary.md` first (integrity status, counts by severity, coverage warning, top findings), then
`technical-report.md` (sections: confirmed observations, heuristic findings, IOC matches, collection errors, areas not
assessed, limitations). `report.json` is the schema-stable machine output; `findings.csv` opens in a spreadsheet
(formula-like cells are prefixed with `'`). Running the same command again fails with "refusing to overwrite" — pick a new
directory.

## 14. Permissions, missing logs and false positives

- `permission_denied` entries in `manifest.json` → artifacts marked `partial`. Decide whether to re-run that collector with
  elevated privileges; never assume "nothing found".
- Missing `auth.log`/journal → the `logs` notes say "authentication telemetry is NOT available"; authentication rules
  are not evaluated.
- False positives: each finding lists them. `LIR-PROC-002` (deleted executable) often follows a package upgrade;
  `LIR-NET-002` flags port numbers any app may use; `LIR-AUTH-003` is normal where root key login is policy.
- A rule that cannot run (missing artifact, failed collector, no baseline) is listed in the notes, not silently ignored.

## 15. Clean up

```bash
rm -rf ./reports/synthetic          # synthetic reports
rm -rf ./evidence                   # ONLY if it holds just test collections; real evidence follows your retention policy
deactivate                          # leave the virtualenv; delete .venv to remove it
```

---

## Exercise 1 — Host investigation (basic live collection)

**Goal:** collect, then identify host information and artifacts.

```bash
python -m linux_ir collect --profile basic --output ./evidence
EV=$(ls -d ./evidence/*/ | tail -1)
python - "$EV" <<'PY'
import json, sys
ev = sys.argv[1]
host = [r for r in json.load(open(ev + "/artifacts/inventory.json"))["records"] if r["kind"] == "host"][0]
print({k: host[k] for k in ("hostname", "pretty_name", "kernel", "architecture", "uptime_seconds")}, host["init"]["name"])
for name in ("inventory", "processes", "network", "persistence", "logs"):
    d = json.load(open(f"{ev}/artifacts/{name}.json"))
    print(f"{name:12} {d['status']:8} records={len(d['records']):<5} errors={len(d['errors'])}")
PY
```

**Expected (illustrative):** a dict with your hostname/distribution/kernel, then one line per artifact with its status.

**Explanation:** `inventory.json` = host facts; `processes.json` = `/proc` snapshot with redacted command lines;
`network.json` = sockets/interfaces/routes; `persistence.json` = systemd/cron/startup/SSH items; `logs.json` = recent SSH/sudo
events (if readable); `manifest.json` = hashes, coverage and errors.

**Verify:** `python -m linux_ir verify-manifest --input "$EV"` → `PASS`. Check `errors` per artifact to see what was not readable.

**Common mistakes:** passing the parent `./evidence` instead of the printed sub-directory; expecting root-only data
(auth log, firewall) from an unprivileged run; forgetting `source .venv/bin/activate`.

**Cleanup:** `rm -rf ./evidence` (test machine only).

## Exercise 2 — Persistence analysis (synthetic systemd/cron)

```bash
CASE=examples/synthetic-evidence/case-001
python -m linux_ir scan --input $CASE | grep -A2 -E "PERS-00(1|2|5)"
python - <<'PY'
import json
recs = json.load(open("examples/synthetic-evidence/case-001/artifacts/persistence.json"))["records"]
for i in (1,):
    r = recs[i]
    print(r["path"], "→", r["exec_start"], "exists:", r["exec_exists"], "sha256:", r["exec_sha256"][:16], "…")
PY
```

**Expected (actual):** `LIR-PERS-002` for `evil-updater.service` (ExecStart under `/tmp`), `LIR-PERS-001` for
`backup.service` (references `/usr/local/bin/missing-backup.sh`, which does not exist), `LIR-PERS-005` for the
`curl … | sh` cron line in `/etc/crontab`; the python snippet prints the unit path, its `ExecStart`, and the binary's hash.

**Explanation:** Rule `LIR-PERS-002` matches `kind = systemd_unit` records whose `exec_binary` starts with `/tmp/`, `/var/tmp/`
or `/dev/shm/`. The rule file is [`rules/persistence.yaml`](../rules/persistence.yaml): read the `when:` block to see
exactly why it matched and the `false_positives:` list to see why it is only *medium confidence*. Nothing was executed:
the unit was parsed as text and the binary only hashed.

**Verify:** the `ref:` printed with each finding points at `artifacts/persistence.json#records[N]`; open the JSON and
confirm record N is the unit.

**Common mistakes:** treating "unfamiliar" as malicious (the rules do not); running `scan` on a directory without
`artifacts/`.

**Cleanup:** nothing was written.

## Exercise 3 — IOC matching and tracing back

```bash
python -m linux_ir scan --input $CASE --iocs examples/iocs.json --json > /tmp/ex3.json
python - <<'PY'
import json
f = [x for x in json.load(open("/tmp/ex3.json")) if x["rule_id"] == "IOC-MATCH-SHA256"]
for x in f:
    print(x["artifact"], x["evidence_ref"], x["evidence"].get("path") or x["evidence"].get("name"))
PY
grep -n "$(python - <<'PY'
import json; print(json.load(open('examples/iocs.json'))['indicators'][0]['value'][:16])
PY
)" $CASE/artifacts/*.json
```

**Expected (actual):** three SHA-256 matches (in `files.json`, `persistence.json`, `processes.json`); the final `grep` shows
the same hash in each file. The IP indicator `203.0.113.50` likewise matches `network.json` and several `logs.json` events.

**Explanation:** the IOC file lists a hash of the harmless synthetic stand-in file. The matcher compares normalised values
for **exact** equality (no substrings), and every match carries `evidence_ref`. The next steps remind you that a match is a
lead, not confirmation.

**Verify:** open the referenced record, e.g. `python -m json.tool $CASE/artifacts/processes.json | less` and find pid 977.
Edit a copy of `examples/iocs.json` (never the original) to a prefix of the hash — the match disappears (no substring matching).

**Common mistakes:** uppercase or short hashes (they are normalised/rejected: an invalid hash makes the whole IOC file
fail validation with exit 1); expecting `evil.example.test` to match `a.evil.example.test` (needs `ioc.match_subdomains: true`).

**Cleanup:** `rm /tmp/ex3.json`

## Exercise 4 — Evidence integrity

```bash
rm -rf /tmp/ex4 && mkdir /tmp/ex4 && cp -r examples/synthetic-evidence/case-001 /tmp/ex4/case
python -m linux_ir verify-manifest --input /tmp/ex4/case; echo "exit=$?"          # PASS
sed -i 's/backup.service/backup2.service/' /tmp/ex4/case/artifacts/persistence.json
python -m linux_ir verify-manifest --input /tmp/ex4/case; echo "exit=$?"          # FAIL
python -m linux_ir scan --input /tmp/ex4/case; echo "exit=$?"                      # refused
python -m linux_ir scan --input /tmp/ex4/case --allow-unverified | head -3
```

**Expected (actual):**

```
Verified files : 5
MODIFIED  : {'path': 'artifacts/persistence.json', 'expected': 'f5bd…9055', 'actual': 'fa54…7b66'}
RESULT: FAIL: evidence differs from manifest
exit=3
error: evidence integrity verification FAILED (modified=1, missing=0, unexpected=0). Re-run with --allow-unverified to analyse anyway.
exit=3
```

(The hashes you see will match the files in your checkout.)

**Explanation:** the manifest holds each file's SHA-256 and size. Any byte change — here a one-word edit — changes the hash, so
verification fails (exit 3) and analysis refuses to run unless you explicitly accept unverified evidence (the report then
shows integrity as FAILED). **Caveat:** an attacker who can edit evidence can also edit `manifest.json`; keep a copy of the
manifest's SHA-256 elsewhere.

**Verify:** also try `rm /tmp/ex4/case/artifacts/logs.json` (reported as MISSING) and `touch /tmp/ex4/case/artifacts/x.json`
(reported as UNEXPECTED).

**Common mistakes:** editing the *original* fixture (restore with `git checkout -- examples`); expecting verification to
detect a rewritten manifest.

**Cleanup:** `rm -rf /tmp/ex4`

---

## Optional: real-host exercises with elevated privileges (separate from the synthetic workflow)

Only on systems you are authorised to examine. Read [security and limitations](security-and-limitations.md) first.

```bash
sudo python -m linux_ir collect --profile extended --collectors logs,network,persistence --output ./evidence-root
sudo chown -R "$USER" ./evidence-root      # so later analysis can run unprivileged
```

You choose to run `sudo`; the toolkit never does. Elevated runs can expose more sensitive data (other users' crontabs,
auth logs, firewall rules) and collection still cannot see through a rootkit or recover deleted data. Compare
`coverage`/`errors` with your unprivileged run to see what the extra privilege added.
