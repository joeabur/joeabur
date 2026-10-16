# Evidence handling

## Layout

```
evidence/<host>-<UTC timestamp>-<random>/        mode 0700, never reused
├── artifacts/{inventory,processes,network,persistence,logs,files}.json   mode 0600
├── imported/…              verbatim copies of --import-log files (if any)
└── manifest.json
```

`manifest.json` records tool name/version, host and platform metadata, profile, collectors requested, start/finish (UTC),
effective uid, per-artifact status/sources/errors/notes, a coverage summary (`ok/partial/failed/skipped/unavailable`), every
file with size and SHA-256, and limitations.

## Integrity

`verify-manifest` recomputes SHA-256 and size per listed file and reports **modified**, **missing**, **unexpected** and
**unsafe** (traversal/symlink) entries; it never modifies evidence; exit code 3 on failure.

A manifest stored beside evidence is **not independently tamper-proof**. Record its SHA-256 (printed by `collect`, also
written to `evidence-manifest.sha256` by `report`) in a separate system or sign it with your own tooling.

## Live response vs forensic acquisition

This is live-response triage. It is **not** a bit-for-bit image, does not preserve memory, free space or file-system
metadata beyond what is listed, alters volatile state and access times, and offers no guarantee of forensic admissibility.
For disk-level evidence on a Mac use dedicated acquisition tooling (and mind FileVault/T2/Apple silicon constraints).

## Chain of custody

Maintain your own record: who collected, when, on which Mac, under what authority, where copies are stored and who accessed
them. Re-run `verify-manifest` after each transfer. Timestamps are host-reported and normalised to UTC; clock accuracy is
not verified.

## Retention and access

Keep evidence on access-controlled (and, where policy requires, encrypted) storage; delete per retention policy; never
commit evidence or reports to version control (`.gitignore` excludes `evidence/`, `reports/`, `analysis/`).
