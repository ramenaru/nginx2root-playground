# Contributing

Thanks for helping improve nginx2root.

## Ground rules

- This is a defensive auditor. Do not add exploitation, payloads, or code that
  modifies nginx configuration.
- Keep the tool read-only and safe to run on a production host.
- Prefer small, focused checks with a clear fix and reference.
- Do not add a dependency unless the value is high; the tool should stay
  usable on a minimal VPS.

## Development

Requirements: Bash 4.4+, `shellcheck`, `jq`, and Docker for integration tests.

```bash
make lint
make test
make integration
```

All three must pass before a pull request is merged.

## Adding a check

1. Register an ID, severity, and title in `register_all_checks` inside
   `nginx2root.sh`.
2. Implement the check in the appropriate `check_*` function.
3. Emit with `emit ID STATUS DETAIL FIX REF`.
   - `status`: `fail`, `warn`, `info`, `pass`, or `skip`.
   - Use `pass`/`skip` so `--verbose` shows coverage.
4. Add a fixture or extend an existing one in `tests/fixtures/`.
5. Add assertions to `tests/run.sh` for both the positive and negative case.
6. Document the check in `docs/checks.md`.
7. Run `make check` and `make integration`.

## Adding an advisory

Add a row to `CVE_DATA`:

```text
"CVE-YYYY-NNNNN|severity|feature|min|max|fixed1,fixed2|summary"
```

- `feature` must match a `feat_*` function or the row is always considered
  relevant.
- `fixed1,fixed2` supports stable and mainline branches. For example
  `1.31.9,1.30.7` means both branches are fixed.
- Add a test for the vulnerable and fixed version if the logic is non-obvious.
- Update `CHANGELOG.md`.

## Style

- Bash with 4-space indentation.
- Quote expansions; keep `shellcheck -S warning` clean.
- No `eval` of configuration content.
- Do not follow untrusted paths or execute config values.

## Reporting bugs

Use the issue template and include:

- `nginx2root --version`
- nginx version
- output of `nginx2root --format json` with secrets removed
- the relevant config snippet (redact domains and paths if needed)
