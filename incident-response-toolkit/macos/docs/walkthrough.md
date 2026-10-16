# Walkthrough: from fresh clone to a finished investigation

Sections 1–6, 11–15, the synthetic demo and Exercises 2–3 use **synthetic evidence only**: no administrator password, no
Full Disk Access, no disabled security setting, no production endpoint, no network (except `pip install` once). They work
on macOS, Linux or WSL. Sections 7–10 and Exercise 1 run **read-only collection on a test Mac**; no privilege is required
for them either, but use a machine you own.

Output marked **(actual)** was produced by running the command in development (on Linux, because that is where the
synthetic workflow was executed). Output marked **(illustrative)** shows the shape of results from a real Mac, which
was *not* available when this document was written: your values will differ.

## 1. Prerequisites and supported macOS versions

macOS 12 Monterey – 15 Sequoia on Apple silicon or Intel; Python 3.11+ (3.12 recommended); `git`. Command-line tools used
by collectors ship with macOS (`sw_vers`, `ps`, `lsof`, `netstat`, `ifconfig`, `log`, `codesign`, …).

## 2. Clone

```bash
git clone <repository-url>
cd incident-response-toolkit/macos
```

## 3–4. Virtual environment and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -c requirements/constraints.txt -e ".[dev]"
```

(`./scripts/setup-dev.sh` does the same.) Leave the environment with `deactivate`.

## 5. Run the test suite

```bash
pytest -q
```

Expected (actual on Linux at time of writing): `147 passed, 3 skipped` (the skips are macOS-only live tests); on macOS the live tests run too. No failures. Tests use a fake
Mac filesystem and mocked command output; they need no privileges.

## 6. Check platform and environment readiness

```bash
python -m mac_ir doctor
```

(illustrative, on a Mac)

```
[OK  ] operating system: macOS 14.4.1
[OK  ] macOS version: 14.4.1 (supported: 12+; older versions are untested)
[OK  ] architecture: arm64
[OK  ] privileges: unprivileged: other users' sockets, system logs and protected paths may be partial
[OK  ] tool:lsof: /usr/sbin/lsof
...
[OK  ] full disk access: not required: protected (TCC) locations are reported as inaccessible, never bypassed
```

(actual, on a Linux machine) `[FAIL] operating system: Linux is not macOS: live collection is unsupported here (analysis,
reporting and manifest verification still work on any OS)` and exit code 1.

## 7. Dry-run collection

```bash
python -m mac_ir collect --dry-run --profile basic --output ./evidence
```

(actual, abridged; works on any OS)

```
DRY RUN: profile=basic; nothing will be collected or written. Output would go under ./evidence/<host>-<UTC time>-<id>/

[inventory] macOS version/build, architecture, uptime, sessions, disk space, SIP/Gatekeeper/FileVault/firewall status
  privileges: No privileges required. Each security query is read-only; failures are recorded, not escalated.
  - run: sw_vers, uname -m, hostname, sysctl -n kern.boottime, who, df -k
...
```

Nothing is created: `ls ./evidence` fails with "No such file or directory".

## 8. Collect basic evidence on a test Mac

```bash
python -m mac_ir collect --profile basic --output ./evidence
EV=$(ls -d ./evidence/*/ | tail -1); echo "$EV"
```

(illustrative)

```
Evidence collected: ./evidence/Marks-Mac-20260310T120000Z-1a2b3c
Manifest SHA-256 (store a copy separately): 9f2c…
  inventory    ok          records=4      errors=0
  logs         partial     records=1      errors=1
  network      ok          records=23     errors=0
  persistence  partial     records=14     errors=2
  processes    ok          records=412    errors=0
  files        skipped     records=0      errors=0
Some data is missing (see manifest errors). Missing data is NOT evidence of absence of activity. ...
EVIDENCE_DIR=./evidence/Marks-Mac-20260310T120000Z-1a2b3c
```

`partial` is normal without administrator rights (for example `log show` may be refused, `/Library/...` items may be
protected). It means "look at the errors", not "something is wrong".

## 9. Inspect the manifest

```bash
python -m json.tool "$EV/manifest.json" | head -60
```

Check `started_at`/`finished_at` (UTC), `privileged`, `coverage` (`ok`/`partial`/`skipped`…), each artifact's `errors`
and `notes`, and `files` (path, size, SHA-256).

## 10. Verify collected files and SHA-256 hashes

```bash
python -m mac_ir verify-manifest --input "$EV"; echo "exit=$?"
```

(actual format)

```
Manifest SHA-256: ee01c5f6717fd6da64289026bf125935aa4b3ce34d86707ce9783880c88df4c5
Verified files : 6
RESULT: PASS: all hashes match
exit=0
```

Copy the manifest SHA-256 to a place outside the evidence directory.

## 11. IOC matching against synthetic evidence

```bash
CASE=examples/synthetic-evidence/case-001
python -m mac_ir verify-manifest --input $CASE
python -m mac_ir scan --input $CASE --iocs examples/iocs.json --baseline examples/synthetic-evidence/baseline > /tmp/scan.txt
head -3 /tmp/scan.txt; grep -c "^\[.*IOC-MATCH" /tmp/scan.txt
```

(actual) `44 finding(s) from 22 rules`: 26 IOC matches plus 18 heuristic findings (16 from rules + 2 baseline `MIR-PERS-005`). IOC matching is exact:
`IOC-MATCH-SHA256`, `-FILE_PATH`, `-PROCESS_NAME`, `-IP`, `-DOMAIN`. Without `--iocs`/`--baseline` the same evidence gives
16 findings.

## 12. Generate and review a report

```bash
python -m mac_ir report --input $CASE --iocs examples/iocs.json \
  --baseline examples/synthetic-evidence/baseline --output ./reports/synthetic
ls ./reports/synthetic
```

(actual)

```
evidence-manifest.json  evidence-manifest.sha256  executive-summary.md  findings.csv  report.json  technical-report.md
```

Read `executive-summary.md` first: integrity status, counts by severity, coverage warning, top findings. Then
`technical-report.md`, which separates **confirmed observations**, **heuristic findings**, **IOC matches**, **collection
errors** and **areas not assessed**, and lists limitations. `report.json` is for automation; `findings.csv` for
spreadsheets (formula-like cells are escaped). Re-running into the same directory fails with "refusing to overwrite".

## 13. Findings, false positives, permission errors and limitations

- Every finding lists **severity** (impact if true) and **confidence** (how likely it is meaningful) separately, a `why`,
  **known false positives**, next steps and an evidence reference.
- Unsigned or unusual launch items are *context*: `MIR-PERS-004` is only low/low and only fires together with a
  non-standard location.
- `permission_denied` entries mean macOS protections (or file modes) blocked a read. The toolkit reports it and moves
  on; it never bypasses TCC/SIP. Unified-log events may be `<private>`, expired or restricted to administrators.
- A rule that cannot run (missing artifact, failed collector, no baseline) is listed in the notes rather than silently
  skipped. **No findings ≠ clean.**

## 14. Fully synthetic demo (no elevated privileges)

```bash
bash scripts/run-demo.sh
```

(actual, abridged) verifies the synthetic manifest, scans with IOCs and baseline, writes reports to a temporary
directory, and compares the result with `examples/expected-results/scan-findings.json`:

```
findings in report: 44; expected: 44
Demo OK
Demo output kept in: /tmp/mac-ir-demo.XXXXXX (delete it when done: rm -rf /tmp/mac-ir-demo.XXXXXX)
```

## 15. Clean up

```bash
rm -rf ./reports/synthetic /tmp/scan.txt     # synthetic outputs
rm -rf /tmp/mac-ir-demo.*                    # demo output
rm -rf ./evidence                            # ONLY if it contains just test collections
deactivate                                   # leave the virtualenv (delete .venv to remove it)
```

---

## Exercise 1 — Run a basic collection and explain each output artifact

```bash
python -m mac_ir collect --profile basic --output ./evidence
EV=$(ls -d ./evidence/*/ | tail -1)
ls -l "$EV" "$EV/artifacts"
python - "$EV" <<'PY'
import json, sys
ev = sys.argv[1]
host = [r for r in json.load(open(ev + "/artifacts/inventory.json"))["records"] if r["kind"] == "host"][0]
print({k: host.get(k) for k in ("hostname", "product_version", "build", "architecture", "uptime_seconds")})
print(host["security_settings"])
for name in ("inventory", "processes", "network", "persistence", "logs"):
    d = json.load(open(f"{ev}/artifacts/{name}.json"))
    print(f"{name:12} {d['status']:8} records={len(d['records']):<5} errors={len(d['errors'])}")
PY
```

**Expected files:** `manifest.json` and `artifacts/{inventory,processes,network,persistence,logs}.json` (`files.json` only
with `--profile extended`). Directory mode `0700`, files `0600`.

**Expected output (illustrative):** a dict with your hostname/version/build/arch, a dict such as
`{'sip': 'System Integrity Protection status: enabled.', 'gatekeeper': 'assessments enabled', ...}`, then one line per artifact.

**What each artifact is:** `inventory` — host facts and *status* of SIP/Gatekeeper/FileVault/firewall; `processes` — `ps`
snapshot with redacted command lines and executable hashes; `network` — `lsof` sockets with owning process, interfaces, routes;
`persistence` — launchd plists (path, owner, mode, hash, program, signing context), your crontab, shell startup files;
`logs` — sshd/sudo/su events from the unified log for the last 24 h plus `log_stats`; `manifest.json` — coverage, errors and
SHA-256 of every file.

**Verify:** `python -m mac_ir verify-manifest --input "$EV"` → `PASS`. Look at each artifact's `errors` to see what was not readable.

**Common mistakes:** passing `./evidence` instead of the printed sub-directory; expecting other users' sockets without
administrator rights; running on Linux (collection is refused; use the synthetic evidence instead).

**Cleanup:** `rm -rf ./evidence`

## Exercise 2 — Match a synthetic IOC and trace the finding back to its evidence

```bash
CASE=examples/synthetic-evidence/case-001
python -m mac_ir scan --input $CASE --iocs examples/iocs.json --json > /tmp/ex2.json
python - <<'PY'
import json
for f in json.load(open("/tmp/ex2.json")):
    if f["rule_id"] == "IOC-MATCH-SHA256":
        print(f["artifact"], f["evidence_ref"], f["evidence"].get("path") or f["evidence"].get("name"))
PY
grep -c "$(python -c "import json; print(json.load(open('examples/iocs.json'))['indicators'][0]['value'][:16])")" $CASE/artifacts/*.json
```

**Expected (actual):**

```
files artifacts/files.json#records[4] /private/tmp/.cache/kworker-upd
persistence artifacts/persistence.json#records[4] /Library/LaunchDaemons/com.example.updater.plist
processes artifacts/processes.json#records[3] kworker-upd
```

followed by per-file counts (1 each in `files.json`, `persistence.json`, `processes.json`, 0 elsewhere).

**Explanation:** `examples/iocs.json` (synthetic, `"synthetic": true`) lists the SHA-256 of a harmless text file. The matcher normalises
values and requires **exact** equality, so the same hash is found in three artifacts. Each match carries `evidence_ref` and
reminds you the match is a lead, not a verdict. Paths compare case-insensitively on macOS by default; domains match only
exactly unless `ioc.match_subdomains: true`.

**Verify:** `python - <<'PY'` … open record 3 of `processes.json` (`json.load(open(...))["records"][3]`) and confirm pid 977,
`exe: /private/tmp/.cache/kworker-upd`. Edit a *copy* of the IOC file to a hash prefix: no match (no substring matching).

**Common mistakes:** uppercase/short hashes (normalised/rejected; an invalid entry fails the whole file with exit 1); expecting
`example.test` to match `evil.example.test`.

**Cleanup:** `rm /tmp/ex2.json`

## Exercise 3 — Modify a synthetic fixture, rerun analysis, compare reports and manifest verification

```bash
rm -rf /tmp/ex3 && mkdir /tmp/ex3
CASE=examples/synthetic-evidence/case-001
cp -r $CASE /tmp/ex3/case
python -m mac_ir report --input $CASE --iocs examples/iocs.json --output /tmp/ex3/before
python - <<'PY'
import json
p = "/tmp/ex3/case/artifacts/persistence.json"
d = json.load(open(p))
for r in d["records"]:
    if r.get("label") == "com.example.updater":      # point the launch item at a normal location
        r["exec_binary"] = "/usr/local/bin/helper"
        r["program_arguments"] = ["/usr/local/bin/helper", "--daemon"]
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
python -m mac_ir verify-manifest --input /tmp/ex3/case; echo "exit=$?"
python -m mac_ir report --input /tmp/ex3/case --iocs examples/iocs.json --output /tmp/ex3/after; echo "exit=$?"
python -m mac_ir report --input /tmp/ex3/case --iocs examples/iocs.json --allow-unverified --output /tmp/ex3/after
python - <<'PY'
import json
b = json.load(open("/tmp/ex3/before/report.json")); a = json.load(open("/tmp/ex3/after/report.json"))
ids = lambda r: sorted({f["rule_id"] for f in r["heuristic_findings"] + r["ioc_matches"]})
print("removed:", sorted(set(ids(b)) - set(ids(a))), "added:", sorted(set(ids(a)) - set(ids(b))))
print("integrity before/after:", b["integrity"]["ok"], a["integrity"]["ok"])
PY
```

**Expected (actual):**

```
Manifest SHA-256: ee01…f4c5
Verified files : 5
MODIFIED  : {'path': 'artifacts/persistence.json', 'expected': 'c590…b1b8', 'actual': '0936…ca60'}
RESULT: FAIL: evidence differs from manifest
exit=3
error: evidence integrity verification FAILED (modified=1, missing=0, unexpected=0). Re-run with --allow-unverified to analyse anyway.
exit=3
… (reports written)
removed: ['MIR-PERS-002'] added:
integrity before/after: True False
```

**Explanation:** verification catches the one-file change (exit 3) and analysis refuses by default. With `--allow-unverified`
the report is produced but records `integrity.ok = false`, and the executive summary warns that verification failed. The
launch item no longer points into `/private/tmp`, so `MIR-PERS-002` disappears and the IOC file-path match for that record
goes away: exactly the kind of silent change the manifest exists to expose. (Hashes shown depend on your checkout.)

**Verify:** `diff <(python -m json.tool /tmp/ex3/before/report.json) <(python -m json.tool /tmp/ex3/after/report.json) | head`
and read `integrity` in each. Also try deleting an artifact (reported `MISSING`) or adding a file (`UNEXPECTED`).

**Common mistakes:** editing the committed fixture instead of the copy (restore: `git checkout -- examples`); expecting
verification to detect a rewritten `manifest.json` (it cannot: store the SHA-256 elsewhere).

**Cleanup:** `rm -rf /tmp/ex3`

---

## Optional: administrator-assisted collection on a test Mac (separate from the synthetic workflow)

Not required by anything above. Running a collector as an administrator exposes more data (all users' sockets, system log
events, all crontabs), including more sensitive personal data, and still cannot bypass SIP/TCC or read protected stores.
Only on a Mac you are authorised to examine:

```bash
sudo python -m mac_ir collect --profile extended --collectors network,logs --output ./evidence-admin
sudo chown -R "$USER" ./evidence-admin
```

The toolkit never runs `sudo` itself. Compare `coverage` and `errors` with your unprivileged run to see what the elevation added.
