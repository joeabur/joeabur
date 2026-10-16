# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `error: rules directory not found` | Run from the repository root, use an editable install, or pass `--rules rules` / set `IR_TOOLKIT_RULES`. |
| `collect` reports `partial` for network | `ss`/`ip` missing (see `doctor`). The toolkit falls back to `/proc/net` without process names. Install `iproute2` yourself; the tool never installs packages. |
| `permission_denied` for `/var/log/auth.log`, firewall, `/root/*` | Expected unprivileged. Decide whether to re-run that collector as root: `sudo python -m linux_ir collect --collectors logs --output ./evidence-root`. Running sudo is always your choice. |
| Processes show `visibility: limited` | `hidepid` mount option, container, or ptrace restrictions. Not evidence of absence. |
| No log events | Journal not readable (add user to `systemd-journal`/`adm` if policy allows), logs rotated beyond window, or non-syslog daemon. The artifact notes state when no source could be read. |
| `init system is '...' not systemd` | Non-systemd host or container: systemd collection is skipped by design; cron/startup/SSH sources still run. |
| Log timestamps look shifted | Classic syslog lines have no year/zone; UTC and the current year are assumed. Prefer `journalctl`/ISO timestamps. |
| `evidence integrity verification FAILED` | Something under the evidence directory changed after collection (modified/missing/unexpected files). Investigate; use `--allow-unverified` only for deliberate exercises. |
| `refusing to overwrite existing file` | Reports and manifests are created with `O_EXCL`. Choose a new `--output`. |
| `error: unknown configuration key` | Config is validated strictly; compare with `configs/default.yaml`. |
| `ModuleNotFoundError: yaml` | Install into the active virtualenv (`pip install -e ".[dev]"`). |
| Rule parse error | Message names file and rule id; see [configuration](configuration.md#rule-files-rulesyaml). |
| Tests fail on non-Linux | Live-host tests are skipped off Linux; others should pass everywhere. File an issue with `pytest -q` output. |
| `ruff format --check` fails | Run `ruff format .`. |
