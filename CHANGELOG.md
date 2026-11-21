# changelog

## 1.1.0

- added suppressions and baseline files with `--suppressions`, `--baseline`, and `--write-baseline`.
- added `--show-suppressed` and suppressed counts in text and json output.
- added sarif 2.1.0 output with `--format sarif` and `--sarif`.
- added a json schema at `docs/n2rpg.schema.json`.
- added a composite github action wrapper in `action.yml`.
- added codeql and dependabot automation.
- added the project watermark.

## 1.0.0

first release.

- added n2rpg. it checks http/2, tls, nginx to root paths, config flaws, network state, and known cves.
- added text and json output, config dumps, filters, and ci exit codes.
- added fixture tests and a docker integration test.
- added the lab. it starts a broken nginx 1.24 container and a hardened current nginx container so you can compare the audit output.
- installs n2rpg, with nginx2root-playground as a longer alias.
