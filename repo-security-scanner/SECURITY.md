# Security policy

## Supported versions

Only the latest released minor version receives security fixes while the project is `0.x`.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on the
repository that hosts this project, or email the maintainer listed on the repository profile.
Please include:

- the affected version (`reposcan version`) and scanner versions (`reposcan doctor --json`);
- a minimal reproduction (a repository layout or report file is ideal);
- the impact you expect (for example "a repository can hide a finding", "secret value appears in a report").

You can expect an acknowledgement within 5 working days and a fix or mitigation plan within 30 days
for confirmed issues. Credit is given unless you prefer otherwise.

## What counts as a vulnerability here

reposcan treats the scanned repository, file names and scanner output as hostile input. These are in
scope:

- a scanned repository suppressing or hiding findings without the operator's explicit configuration;
- command or argument injection, path traversal, symlink escape, unsafe deserialisation;
- HTML, Markdown, SARIF or workflow-command injection through report content;
- a credential value (not its redacted form) reaching a log, console line, report or CI artifact;
- a scanner failure, timeout or truncated output being reported as a clean result;
- transmission of source or findings to a third party without explicit configuration.

Findings in the *intentionally vulnerable* fixtures under `sample-data/` and the synthetic
credentials in `tests/` and `docs/` are not vulnerabilities; they are test data. Weaknesses in the
third-party scanners themselves should be reported to those projects.

## Handling secrets while contributing

Never commit real credentials, not even in tests. Synthetic credentials must be obviously fake and
either assembled at runtime in tests or match the `DEMO_TOKEN_*` rule defined in
`src/reposcan/data/gitleaks.toml`. See `docs/security-and-limitations.md`.
