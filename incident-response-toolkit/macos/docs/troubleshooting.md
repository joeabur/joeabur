# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `live collection is only supported on macOS` | You are on Linux/Windows. Use `--dry-run`, or analyse evidence collected on a Mac. |
| `[WARN] macOS version … older versions are untested` | macOS < 12. Collection may work but is unsupported. |
| `permission_denied` for `/Library/...`, `~/Library/...` or a plist | macOS privacy protections (TCC/SIP) or file mode. The toolkit **does not bypass** them. Decide whether to grant access in your own policy-compliant way (e.g. run the terminal as an administrator) and re-run that collector. |
| `lsof` shows few sockets, no process for others | Without root `lsof` only sees your processes. The `netstat` fallback lists other sockets without process names. |
| `log show` returns nothing / error | System logs usually need an administrator; the artifact says whether the source was readable. Narrow `logs.window_hours` or the predicate if output hits the size cap (`truncated`). |
| `<private>` in events | Unified logging redacts dynamic strings; counted in `redacted_events`. Not recoverable by this tool. |
| `codesign … not_found` / errors | `extended` only; Xcode command-line tools are not required, but `/usr/bin/codesign` must exist. Signing info is optional context. |
| `parse_error` for a plist | Corrupt or non-plist file in a LaunchDaemons/Agents directory. It is reported, never executed. |
| Process start times look off | `ps lstart` is host-local time; the toolkit assumes UTC when normalising. Compare with `inventory.boot_time`. |
| `error: rules directory not found` | Use an editable install from the repo root, or `--rules rules`, or `IR_TOOLKIT_RULES`. |
| `evidence integrity verification FAILED` | Files changed after collection; investigate. `--allow-unverified` only for deliberate exercises. |
| `refusing to overwrite existing file` | Reports/manifests are created exclusively; choose a new `--output`. |
| `ModuleNotFoundError: yaml` | Activate the virtualenv and `pip install -e ".[dev]"`. |
| Tests fail on Linux/Windows | macOS-only tests are skipped there; others should pass. Report with `pytest -q` output. |
| `ruff format --check` fails | `ruff format .` |
