# changelog

## 1.0.0

first release.

- added n2rpg. it checks http/2, tls, nginx to root paths, config flaws, network state, and known cves.
- added text and json output, config dumps, filters, and ci exit codes.
- added fixture tests and a docker integration test.
- added the lab. it starts a broken nginx 1.24 container and a hardened current nginx container so you can compare the audit output.
- installs n2rpg, with nginx2root-playground as a longer alias.
