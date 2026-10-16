# Examples (synthetic data)

All commands run from the `linux/` directory with the virtualenv active and need no root or network.

```bash
# Verify the committed synthetic manifest
python -m linux_ir verify-manifest --input examples/synthetic-evidence/case-001

# Detections only
python -m linux_ir scan --input examples/synthetic-evidence/case-001

# Detections + baseline diff + IOCs, machine-readable
python -m linux_ir scan --input examples/synthetic-evidence/case-001 \
  --iocs examples/iocs.json --baseline examples/synthetic-evidence/baseline --json

# Fail a CI job when anything is found
python -m linux_ir scan --input examples/synthetic-evidence/case-001 --fail-on-findings; echo $?   # 10

# Reports
python -m linux_ir report --input examples/synthetic-evidence/case-001 --iocs examples/iocs.json \
  --output /tmp/linux-ir-report-example

# Seal hand-made evidence (artifacts/*.json only) so it can be verified
python -m linux_ir seal --input ./my-imported-evidence

# Dry run of the extended profile
python -m linux_ir collect --dry-run --profile extended --output ./evidence

# Only authentication-related collectors with a 6 hour window and an imported log
python -m linux_ir collect --collectors logs,persistence --log-hours 6 \
  --import-log ./exported-auth.log --output ./evidence
```

Files: [`examples/iocs.json`](../examples/iocs.json), [`examples/synthetic-evidence/`](../examples/synthetic-evidence),
[`examples/expected-results/`](../examples/expected-results) (`scan-findings.json`, `verify-manifest.txt`).

The synthetic evidence is produced by [`scripts/make-synthetic-evidence.py`](../scripts/make-synthetic-evidence.py) from
an invented fake root filesystem ([`tests/fixtures/rootfs_builder.py`](../tests/fixtures/rootfs_builder.py)): documentation
IP ranges (RFC 5737), `*.example.test` domains and a harmless text file standing in for a malicious binary. Owner names
and the host fields (kernel/architecture) come from the machine that generated the fixtures.
