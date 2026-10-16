# Evidence handling

## Layout

```
evidence/<host>-<UTC timestamp>-<random>/        mode 0700, never reused
├── artifacts/{inventory,processes,network,persistence,logs,files}.json   mode 0600
├── imported/…              verbatim copies of --import-log files (if any)
└── manifest.json
```

`manifest.json` records: tool name/version, host and platform metadata, profile, collectors requested, start/finish times
(UTC), effective uid / privileged flag, per-artifact status, sources, errors and notes, a coverage summary
(`ok/partial/failed/skipped/unavailable`), every file with size and SHA-256, and limitations.

## Integrity

`verify-manifest` recomputes SHA-256 and size for each listed file and reports **modified**, **missing**, **unexpected**
(present but not listed) and **unsafe** (traversal or symlink) entries. It never modifies evidence. Exit code 3 on failure.

A manifest stored beside evidence is **not independently tamper-proof**: whoever can alter evidence can also rewrite the
manifest. Record the manifest SHA-256 (printed by `collect`, also written to `evidence-manifest.sha256` by `report`) in a
separate system (ticket, write-once store) or sign the manifest with your own tooling.

## Collection scope and limitations

- Live response, not forensic acquisition: running the tool changes memory, access times and caches.
- Only selected categories are collected; browser profiles, keys, credential stores and `shadow` contents never are.
- Timestamps are normalised to UTC from host-reported values; clock skew is not corrected.
- Partial collection is labelled explicitly; absence of data is not absence of activity.

## Chain of custody

The toolkit produces hashes and timestamps, not custody records. Maintain your own log: who collected, when, on which
host, under what authority, where copies are stored and who accessed them. Transfer evidence only over channels approved
by your organisation; re-run `verify-manifest` after each transfer.

## Retention and access

Keep evidence on access-controlled storage (0700 directories are a minimum), encrypt at rest where policy requires,
delete according to retention policy, and never commit evidence or reports to version control (`.gitignore` excludes
`evidence/`, `reports/`, `analysis/`).
