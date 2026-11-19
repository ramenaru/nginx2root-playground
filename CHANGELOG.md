# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-20

### Added

- Single-file `nginx2root` auditor for HTTP/2 and nginx -> root flaws.
- Config acquisition through `nginx -T`, `sudo -n`, or a direct recursive read.
- Block-aware awk parser with source file/line tracking.
- HTTP/2 checks: deprecated syntax, h2c, stream limits, `keepalive_requests`,
  Rapid Reset, `http2_push`, live ALPN.
- TLS checks: legacy protocols, weak ciphers, HSTS, certificate expiry,
  private-key permissions, OCSP, client-cert mode, live TLS 1.0/1.1 probes.
- Privilege checks: root workers, writable config/binary/web root, risky
  includes, pid file location, capabilities, systemd hardening.
- Config flaw checks: alias traversal, dotfiles, public `stub_status`,
  unauthenticated WebDAV, dynamic `proxy_pass`, sensitive `root`, and more.
- Built-in advisory table with branch-aware stable/mainline version matching.
- Offline dump mode, JSON output, severity filters, check filters, and
  CI-friendly exit codes.
- Fixture regression tests, Docker integration test, shellcheck CI, docs, and
  install/uninstall helper.

[1.0.0]: https://github.com/OWNER/nginx2root/releases/tag/v1.0.0
