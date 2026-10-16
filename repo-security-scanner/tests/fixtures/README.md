# Test fixtures

## `scanner-output/` (real, sanitised scanner output)

Captured by `scripts/capture_fixtures.py` on 2026-10-16 by running the real scanners (Gitleaks 8.30.1,
Semgrep 1.181.0, Trivy 0.76.0, OSV-Scanner 2.7.0) through reposcan's own adapters against the bundled
repositories in `sample-data/`. Sanitisation: absolute paths replaced by `/repo`, timing/profiling and
volatile ids removed, long descriptions/reference lists trimmed. They contain **no real credentials**: the
only secrets in the source repositories are synthetic and Gitleaks was run with `--redact=100`.

| File | Source repository | Scanner exit code when captured |
|---|---|---|
| `gitleaks-demo.json` | `sample-data/demo-repo` | 10 (leaks found) |
| `gitleaks-clean.json` | `sample-data/clean-repo` | 0 |
| `semgrep-demo.json` | `sample-data/demo-repo` | 0 |
| `semgrep-clean.json` | `sample-data/clean-repo` | 0 |
| `trivy-demo.json` | `sample-data/demo-repo` | 0 |
| `trivy-clean.json` | `sample-data/clean-repo` | 0 |
| `osv-scanner-demo.json` | `sample-data/demo-repo` (`mode = "local-db"`) | 1 (vulnerabilities found) |
| `osv-scanner-clean.json` | `sample-data/clean-repo` | 0 |

Dependency findings reflect the advisory databases of the capture date; the tests assert structure and a
few stable CVEs (for example `CVE-2019-10906`), not exact totals that could drift when re-captured.

## `sarif-schema-2.1.0.json`

The official OASIS SARIF 2.1.0 JSON schema (errata01), used to validate SARIF offline.
SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`; fetched on 2026-10-16 from the
`oasis-tcs/sarif-spec` repository (`sarif-2.1/schema/sarif-schema-2.1.0.json`).

## Hand-written inputs

Malformed-JSON, oversized-output, wrong-shape and failure-mode inputs are generated inline in
`tests/unit/test_adapters.py` through fake scanner executables (`tests/helpers.py`), so no unsafe payload
is stored in the repository.
