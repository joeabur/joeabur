# Examples

All configurations below are validated by the test-suite (`tests/integration/test_docs.py` parses
every TOML block that contains `[baseline]` and `[scan]`, and every file in
`examples/`). Paths are illustrative. Output samples referenced here are **real output of
`scripts/demo.sh`** captured by `scripts/generate-samples.sh` with the temporary path rewritten
to `/tmp/fim-demo`; they are in [sample-data/](../sample-data/).

## 1. Minimal configuration

```toml
[baseline]
dir = "/var/lib/fim/baselines"

[scan]
roots = ["/etc"]
```

## 2. Web server (`examples/web-server.toml`)

Signed baselines, TLS material critical, application code edits high, volatile storage and logs
excluded: see [examples/web-server.toml](../examples/web-server.toml).

## 3. Identity and remote access (`examples/ssh-and-auth.toml`)

Low alert threshold so that even a `metadata_changed` is visible:
[examples/ssh-and-auth.toml](../examples/ssh-and-auth.toml).

## 4. Excluding high-churn paths

```toml
[baseline]
dir = "/var/lib/fim/baselines"

[scan]
roots = ["/etc", "/opt/app"]
exclude = [
  "/opt/app/var/**",           # runtime data: whole subtree
  "/opt/app/**/*.pyc",         # bytecode anywhere below
  "/etc/*.lock",               # direct children only
  "/etc/cups/subscriptions.conf*",
]
```

## 5. Raising severity for specific paths

```toml
[baseline]
dir = "/var/lib/fim/baselines"

[scan]
roots = ["/etc"]

[policy]
alert_threshold = "high"

[[policy.rules]]
name = "cron"
paths = ["/etc/cron*/**", "/etc/crontab"]
severity = "critical"
```

Specific rules come first; the first match wins.

## 6. SIEM (`examples/siem-syslog.toml`) and rsyslog forwarding

[examples/siem-syslog.toml](../examples/siem-syslog.toml) sends CEF over TCP;
[examples/rsyslog-forward.conf](../examples/rsyslog-forward.conf) forwards locally logged RFC 5424
events. Real examples of both formats:
[sample-data/sample-report.cef](../sample-data/sample-report.cef),
[sample-data/sample-report.syslog](../sample-data/sample-report.syslog).

## 7. Scheduling

systemd: `systemd/fim-scan.timer` (installed by `scripts/install.sh --with-systemd`). Cron:
[examples/cron.example](../examples/cron.example).

## 8. Working with reports

Select only critical events from a JSON report with the Python standard library:

```bash
python3 - <<'PY'
import json
r = json.load(open("sample-data/sample-report.json"))
for e in r["events"]:
    if e["severity"] in ("high", "critical"):
        print(e["severity"], e["event_type"], e["path"])
PY
```

Convert a saved report (no rescan):

```bash
fim report convert sample-data/sample-report.json --format text
fim report convert sample-data/sample-report.json --format cef --output /tmp/report.cef
```

Load the CSV in a spreadsheet safely: cells starting with `=`, `+`, `-` or `@` are already
prefixed with `'`.

## 9. Sample artifacts

| File | What it is |
|---|---|
| [sample-data/sample-report.json](../sample-data/sample-report.json) | Full JSON report (validates against [schemas/report.schema.json](schemas/report.schema.json)) |
| [sample-data/sample-report.csv](../sample-data/sample-report.csv) | Events CSV (19 columns) |
| [sample-data/sample-report.issues.csv](../sample-data/sample-report.issues.csv) | Issues CSV (empty: the demo scan was complete) |
| [sample-data/sample-report.cef](../sample-data/sample-report.cef) | CEF lines |
| [sample-data/sample-report.syslog](../sample-data/sample-report.syslog) | RFC 5424 lines |
| [sample-data/sample-fim.toml](../sample-data/sample-fim.toml) | The configuration the demo used |

## 10. An incomplete scan (illustrative)

This excerpt is **illustrative**, hand-trimmed from a real run with `max_files = 3`:

```text
Scan status: INCOMPLETE
Entries scanned: 4
Events: 0

Scan issues (these paths were NOT fully verified):
  limit_reached          /srv/data/f3  max_files=3 exceeded

Result: INCOMPLETE
```

The process exits `3`; no deletions are reported because the walk did not finish.
