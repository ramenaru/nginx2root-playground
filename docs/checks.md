# Check catalog

This page documents every check that `n2rpg` can emit. Run
`n2rpg --list-checks` for the same list on an installed copy, or
`n2rpg --list-cves` for the advisory table alone.

- **110 checks**: 78 configuration/runtime checks plus 32 built-in advisories.
- Checks are **read-only**. Nothing is written, reloaded, or exploited.
- A check can emit `pass` or `skip` as well as a finding. Use `--verbose` to
  see passes and skips, or read the `status` field in JSON output.
- CVE checks run only when the nginx version is known *and* the affected
  feature is actually enabled in the configuration.

## Severity

| Severity | Meaning |
| -------- | ------- |
| `critical` | Direct path from a web request or local user to root/host compromise. Fix immediately. |
| `high` | Serious exposure or a reliable privilege-escalation primitive. Fix before exposing the host. |
| `medium` | Meaningful weakness that needs a second condition or local access. |
| `low` | Hardening gap or defense-in-depth issue. |
| `info` | Context, inventory, or a best-practice suggestion. Not a vulnerability by itself. |

`--fail-on` compares against these levels. `--min-severity` only filters
displayed output; it does not change what is checked or the exit code.

## Status values

| Status | Meaning |
| ------ | ------- |
| `fail` | The check found the condition it looks for. |
| `warn` | A weaker or configuration-dependent form of the condition. |
| `info` | Observation; review it but it may be intentional. |
| `pass` | The check ran and found no problem. |
| `skip` | The check could not run (offline dump, missing tool, not root, no TLS). |

## Selecting checks

IDs are stable. Prefixes select a whole group:

```bash
n2rpg --only H2,TLS
n2rpg --exclude NET,CVE
n2rpg --only ROOT-00
n2rpg --min-severity high
```

---

## ENV: environment

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `ENV-001` | info | nginx binary was found (or skipped in offline mode). | No action. |
| `ENV-002` | info | nginx version detected; a warning means CVE checks are disabled. | Pass `--nginx-version x.y.z` or run where `nginx -v` works. |
| `ENV-003` | critical | `nginx -t` rejected the loaded configuration. | Fix the syntax error before reloading. |
| `ENV-004` | info | nginx is not running, so runtime checks are limited. | Start nginx for process, listener, and permission checks. |
| `ENV-005` | info | The audit is running unprivileged, so some permission checks are incomplete. | Re-run with `sudo` for the full audit. |

## H2: HTTP/2

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `H2-001` | info | HTTP/2 is not enabled anywhere. | Add `http2 on;` to TLS server blocks (1.25.1+) or `listen 443 ssl http2;` on older nginx. |
| `H2-002` | low | Deprecated `listen ... http2` syntax is used on nginx 1.25.1+. | Use `listen 443 ssl;` plus `http2 on;`. |
| `H2-003` | medium | HTTP/2 is enabled for a non-TLS listener (h2c), including a global `http2 on;`. | Enable HTTP/2 only on TLS listeners. |
| `H2-004` | medium | `http2_max_concurrent_streams` is greater than 128. | Lower it to 128 or less. |
| `H2-005` | medium | `keepalive_requests` is greater than 1000, increasing stream-flood impact. | Set `keepalive_requests 1000;`. |
| `H2-006` | high | nginx predates 1.25.3 (CVE-2023-44487, Rapid Reset) with HTTP/2 enabled and no limiting `keepalive_requests`. A warning is emitted for newer builds with a high limit. | Upgrade to 1.25.3+ and keep `keepalive_requests` at 1000 or lower. |
| `H2-007` | info | `http2_push` is configured; server push is deprecated and removed in 1.25.1+. | Remove the directive. |
| `H2-008` | high | A live TLS server block with HTTP/2 configured did not negotiate ALPN `h2`. | Check the listener, SNI, certificate, and client ALPN offer. |
| `H2-009` | info | A live TLS server block negotiated `h2` although HTTP/2 is not enabled for that block. | Confirm whether HTTP/2 is intended for the virtual host. |
| `H2-010` | low | `http2` has an unexpected value. | Use `http2 on;` or `http2 off;`. |

Live checks (`H2-008`, `H2-009`, `TLS-012`, `TLS-014`, `TLS-017`, `NET-004`)
require `--live` (implied for a normal live audit) and `openssl`/`curl`. They
connect only to `--host`/`--port`, defaulting to `127.0.0.1:443`.

## TLS

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `TLS-001` | high | A TLS server enables TLS 1.0, TLS 1.1, or SSLv3. | Use `ssl_protocols TLSv1.2 TLSv1.3;`. |
| `TLS-002` | high | A cipher list contains NULL, EXPORT, RC4, DES, MD5, or anonymous ciphers. | Use a modern Mozilla-style cipher list. |
| `TLS-003` | low | `ssl_prefer_server_ciphers off`. | Set it to `on` unless there is a specific reason. |
| `TLS-004` | medium | A TLS server does not send `Strict-Transport-Security`. | Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`. |
| `TLS-005` | low | HSTS `max-age` is below 180 days (15552000 seconds). | Raise it to one year once HTTPS is stable. |
| `TLS-006` | high | A configured certificate is expired or expires within 30 days. | Renew it and reload nginx. |
| `TLS-007` | critical | A private key is group-readable or world-readable. | `chmod 600`, root ownership. |
| `TLS-008` | info | A self-signed certificate is in use. | Use a publicly trusted certificate for public services. |
| `TLS-009` | low | OCSP stapling is not enabled. | Enable `ssl_stapling` and `ssl_stapling_verify` with a resolver. |
| `TLS-010` | medium | OCSP stapling is enabled without a `resolver`. | Add `resolver 1.1.1.1 8.8.8.8 valid=300s;`. |
| `TLS-011` | medium | `ssl_verify_client optional_no_ca` accepts unverified client certificates. | Prefer `on` with a trusted CA. |
| `TLS-012` | high | The live listener still accepts TLS 1.0 or TLS 1.1. | Disable legacy protocols in nginx and at the load balancer. |
| `TLS-013` | low | The TLS session cache is disabled. | Use `ssl_session_cache shared:SSL:10m;` for performance. |
| `TLS-014` | medium | The live certificate does not match the probed `server_name`. | Check `server_name`, SNI, and certificate SANs. |
| `TLS-015` | high | A TLS listener has no `ssl_certificate`. | Add the certificate/key pair or remove `ssl` from the listener. |
| `TLS-016` | low | The HSTS header lacks `always`, so error responses omit it. | Add `always` to the `add_header` line. |
| `TLS-017` | medium | The live certificate is expired or expires within 30 days. | Renew the certificate and reload nginx. |

## ROOT: nginx to root

These checks look for ways a web compromise or a local user can turn nginx's
privileges into host compromise.

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `ROOT-001` | critical | Worker processes are running as root. | Set `user www-data;` (or another unprivileged account) and reload. |
| `ROOT-002` | critical | The `user` directive names root or UID 0. | Use an unprivileged account. |
| `ROOT-003` | critical | `master_process off` while nginx runs as root; requests are handled by the root process. | Restore the master/worker model. |
| `ROOT-004` | critical | A configuration file is world-writable, group-writable, or writable by a non-root owner. | `chown root:root`, `chmod 644`, and restrict write access to root. |
| `ROOT-005` | critical | A configuration directory is writable by a non-root user or group. | Remove group/world write access. |
| `ROOT-006` | high | An `include` comes from `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, or a world-writable directory. | Keep includes under a root-owned directory such as `/etc/nginx`. |
| `ROOT-007` | critical | The nginx binary is writable by others or owned by a non-root user. | `chown root:root`, `chmod 755`. |
| `ROOT-008` | high | A web content directory is world-writable or writable by the nginx worker user. | Make content root-owned and read-only to nginx. |
| `ROOT-009` | high | The PID file directory is world-writable. | Move the PID file to `/run` or another root-owned directory. |
| `ROOT-010` | high | The nginx master has excessive capabilities such as `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE`. | Restrict the unit to `CAP_NET_BIND_SERVICE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_CHROOT`. |
| `ROOT-011` | low | The systemd unit lacks at least three hardening directives. | Add `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `CapabilityBoundingSet`. |
| `ROOT-012` | high | A systemd `Exec*` line runs a script writable by a non-root user. | Make the script root-owned and not writable by others. |
| `ROOT-013` | low | SELinux/AppArmor is not enforcing, or no MAC tooling is present. | Enable a profile for nginx. |
| `ROOT-014` | low | The worker user has an interactive login shell. | Use `/usr/sbin/nologin`. |
| `ROOT-015` | medium | An `auth_basic_user_file` is world-readable. | `chmod 640` and restrict it to the nginx group. |
| `ROOT-016` | info | An `env` directive exposes a variable to workers. | Do not put secrets in nginx environment variables. |

File permission checks (`ROOT-004` through `ROOT-009`) are skipped for an
offline dump. `ROOT-010` needs a readable `/proc/<pid>/status` and `capsh`.

## CFG: configuration flaws

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `CFG-001` | low | `server_tokens` is not `off`, exposing the nginx version. | Set `server_tokens off;`. |
| `CFG-002` | medium | `autoindex on;` enables directory listings. | Remove it or add authentication. |
| `CFG-003` | high | `stub_status` is publicly reachable or not explicitly denied. | Put it behind `allow 127.0.0.1; deny all;` or authentication. |
| `CFG-004` | high | Alias traversal: a prefix `location` without a trailing slash maps to an `alias` with one. Also warns for `alias` inside regex/named locations. | Add the trailing slash or use `root`; audit capture groups. |
| `CFG-005` | medium | `merge_slashes off` allows duplicate-slash filter bypasses. | Keep it on unless a legacy backend requires otherwise. |
| `CFG-006` | medium | A `root` is configured but no rule blocks dotfiles such as `.git`, `.env`, or `.htpasswd`. | Add a deny rule for dotfiles, excluding `.well-known`. |
| `CFG-007` | high | WebDAV write methods (`PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`) are enabled without authentication or IP restriction. | Require auth/allow rules or disable `dav_methods`. |
| `CFG-008` | medium | `proxy_pass` uses a variable; a finding is elevated when it uses a client-controlled `$http_*` header (SSRF). | Pin the upstream, validate with `map`, and never use `$http_*`. |
| `CFG-009` | low | A TLS server does not send `X-Content-Type-Options`. | Add `add_header X-Content-Type-Options nosniff always;`. |
| `CFG-010` | info | A TLS server has neither `X-Frame-Options` nor a CSP. | Add `frame-ancestors` or `X-Frame-Options`. |
| `CFG-011` | high | `root`/`alias` points at `/`, `/etc`, `/root`, `/home`, `/proc`, `/sys`, `/dev`, or `/var/lib`. | Point it at a dedicated content directory. |
| `CFG-012` | high | A server listens on port 443 without TLS. | Add `ssl` and a certificate, or use a different port. |
| `CFG-013` | info | No explicit `default_server` on port 80 and/or 443. | Add a catch-all server block that rejects unknown Host headers. |
| `CFG-014` | low | `proxy_pass` appears inside an `if` block. | Use `map` or named locations. |
| `CFG-015` | info | Access logging is disabled. | Keep logs unless privacy requirements forbid them. |
| `CFG-016` | medium | `client_max_body_size` is `0` (unlimited) at http or server level. | Set a realistic limit such as `10m`. |
| `CFG-017` | low | `underscores_in_headers on`. | Leave it off; underscore headers are a common filter bypass. |
| `CFG-018` | low | `ignore_invalid_headers off`. | Keep invalid-header rejection enabled. |
| `CFG-019` | medium | A `return` or `rewrite` redirects to plaintext `http://`. | Redirect to `https://` or a relative URI. |
| `CFG-020` | low | No `limit_req` or `limit_conn` rules exist. | Rate-limit login and API locations on internet-facing hosts. |
| `CFG-021` | info | `server_name _` is used without `default_server`. | Add `default_server` to make the catch-all explicit. |
| `CFG-022` | low | `client_header_timeout`, `client_body_timeout`, or `send_timeout` exceeds 300 seconds. | Lower them to limit slowloris. |
| `CFG-023` | low | `large_client_header_buffers` uses a size above 32k. | Use `4 8k` or similar. |
| `CFG-025` | medium | Dynamic `proxy_pass` is used without a `resolver`. | Add a `resolver` with `valid=` and use variables only where required. |

## NET: network and live headers

| ID | Severity | Finding | Fix |
| -- | -------- | ------- | --- |
| `NET-001` | info | Inventory of local listeners on 80/443. | Confirm the expected ports are exposed. |
| `NET-002` | info | nginx owns at least one listener on 80/443, or no nginx process was visible. | Run as root or check which process owns the port. |
| `NET-003` | info | A non-nginx process is visible on 80/443. | Confirm that the expected process owns the public ports. |
| `NET-004` | low | The live `Server` header reveals the nginx version. | Set `server_tokens off;` and consider hiding the header at the edge. |
| `NET-005` | info | At least one listener uses IPv6. | No action; confirm IPv6 firewall rules. |
| `NET-006` | info | Live probes were skipped or could not connect. | Check `--host`/`--port`, nginx state, and that `openssl` is installed. |

`NET-001` through `NET-003` are skipped for offline dumps and remote probe
hosts, because they inspect the local machine only.

---

## CVE advisories

Each advisory is gated on the affected feature being enabled. For example,
`CVE-2026-123007` is reported only when HTTP/2 is enabled; a DAV advisory is
reported only when `dav_methods` is active.

Version ranges are inclusive. The **fixed** column uses the branch-aware form
`mainline,stable`: both `1.31.9+` and `1.30.7+` are fixed for
`1.31.9,1.30.7`, while `1.31.0` is still vulnerable.

| ID | Severity | Feature gate | Affected | Fixed | Summary |
| -- | -------- | ------------ | -------- | ----- | ------- |
| `CVE-2026-123007` | critical | `http2` | 1.9.5 - 1.31.8 | 1.31.9, 1.30.7 | Memory corruption in HTTP/2 flow control |
| `CVE-2026-123633` | medium | `http2` | 1.19.7 - 1.31.8 | 1.31.9, 1.30.7 | Use-after-free in HTTP/2 |
| `CVE-2026-121810` | medium | `http3` | 1.25.0 - 1.31.8 | 1.31.9, 1.30.7 | Use-after-free in HTTP/3 |
| `CVE-2026-118899` | high | `tls` | 1.13.0 - 1.31.8 | 1.31.9, 1.30.7 | Infinite loop reading a TLS 1.3 request body |
| `CVE-2026-125283` | medium | `alias_try_files` | 0.9.6 - 1.31.8 | 1.31.9, 1.30.7 | Buffer overflow with alias and try_files |
| `CVE-2026-15176` | high | `alias_rewrite` | 0.1.29 - 1.31.6 | 1.31.7, 1.30.6 | Buffer overflow with alias and rewrite |
| `CVE-2026-97629` | high | `tls_tickets` | 1.23.2 - 1.31.6 | 1.31.7, 1.30.6 | Session forgery with TLS session tickets |
| `CVE-2026-95101` | medium | `http3` | 1.25.0 - 1.31.6 | 1.31.7, 1.30.6 | Request body injection in HTTP/3 |
| `CVE-2026-97205` | medium | `aio` | 0.8.11 - 1.31.6 | 1.31.7, 1.30.6 | Use-after-free with asynchronous file I/O |
| `CVE-2026-90439` | medium | `http3` | 1.29.2 - 1.31.5 | 1.31.6, 1.30.5 | Buffer overflow in the HTTP/3 module |
| `CVE-2026-42533` | critical | `map_regex` | 0.9.6 - 1.31.2 | 1.31.3, 1.30.4 | Buffer overflow with map and regex |
| `CVE-2026-60005` | medium | `slice` | 1.15.8 - 1.31.2 | 1.31.3, 1.30.4 | Memory disclosure in the slice module |
| `CVE-2026-56434` | medium | `ssi` | 0.8.11 - 1.31.2 | 1.31.3, 1.30.4 | Use-after-free in the SSI module |
| `CVE-2026-42530` | high | `http3` | 1.31.0 - 1.31.1 | 1.31.2 | Use-after-free in HTTP/3 |
| `CVE-2026-42055` | medium | `grpc` | 1.13.10 - 1.31.1 | 1.31.2, 1.30.3 | Buffer overflow in proxy_v2/grpc modules |
| `CVE-2026-9256` | medium | `rewrite` | 0.1.17 - 1.31.0 | 1.31.1, 1.30.2 | Buffer overflow in the rewrite module |
| `CVE-2026-42926` | medium | `http2_proxy` | 1.29.4 - 1.30.0 | 1.31.0, 1.30.1 | HTTP/2 request injection via the proxy module |
| `CVE-2026-42945` | medium | `rewrite` | 0.6.27 - 1.30.0 | 1.31.0, 1.30.1 | Buffer overflow in the rewrite module |
| `CVE-2026-42946` | medium | `scgi_uwsgi` | 0.8.42 - 1.30.0 | 1.31.0, 1.30.1 | Buffer overread in SCGI/uWSGI modules |
| `CVE-2026-40460` | medium | `http3` | 1.25.0 - 1.30.0 | 1.31.0, 1.30.1 | HTTP/3 address spoofing |
| `CVE-2026-40701` | medium | `ocsp` | 1.19.0 - 1.30.0 | 1.31.0, 1.30.1 | Resolver use-after-free in OCSP |
| `CVE-2026-27654` | medium | `dav` | 0.5.13 - 1.29.6 | 1.29.7, 1.28.3 | Buffer overflow in the DAV module |
| `CVE-2026-28753` | medium | `auth_http` | 0.6.27 - 1.29.6 | 1.29.7, 1.28.3 | Injection in auth_http and XCLIENT |
| `CVE-2025-23419` | medium | `tls` | 1.11.4 - 1.27.3 | 1.27.4, 1.26.3 | TLS session reuse vulnerability |
| `CVE-2024-7347` | low | `mp4` | 1.5.13 - 1.27.0 | 1.27.1, 1.26.2 | Buffer overread in the mp4 module |
| `CVE-2024-24990` | high | `http3` | 1.25.0 - 1.25.3 | 1.25.4 | Use-after-free in HTTP/3 |
| `CVE-2021-23017` | medium | `resolver` | 0.6.18 - 1.20.0 | 1.21.0, 1.20.1 | 1-byte memory overwrite in the resolver |
| `CVE-2019-9511` | high | `http2` | 1.9.5 - 1.17.2 | 1.17.3, 1.16.1 | HTTP/2 DoS via small window updates |
| `CVE-2019-9513` | medium | `http2` | 1.9.5 - 1.17.2 | 1.17.3, 1.16.1 | HTTP/2 DoS via priority changes |
| `CVE-2018-16843` | medium | `http2` | 1.9.5 - 1.15.5 | 1.15.6, 1.14.1 | HTTP/2 memory exhaustion |
| `CVE-2018-16844` | medium | `http2` | 1.9.5 - 1.15.5 | 1.15.6, 1.14.1 | HTTP/2 CPU exhaustion |
| `CVE-2017-7529` | medium | `range` | 0.5.6 - 1.13.2 | 1.13.3, 1.12.1 | Integer overflow in the range filter |

### Feature gates

| Gate | Enabled when |
| ---- | ------------ |
| `http2` | HTTP/2 is enabled by `http2 on` or `listen ... http2`. |
| `http3` | `http3 on` or `listen ... quic` is present. |
| `tls` | At least one TLS server block exists. |
| `alias_try_files` | An `alias` location also contains `try_files`. |
| `alias_rewrite` | An `alias` location also contains `rewrite`. |
| `tls_tickets` | TLS session tickets are not disabled. |
| `aio` | `aio` is set to anything other than `off`. |
| `map_regex` | A `map` block contains a regex entry. |
| `slice` | Any `slice` directive is present. |
| `ssi` | `ssi on` is present. |
| `grpc` | `grpc_pass` or `proxy_pass grpc://` is present. |
| `rewrite` | Any `rewrite` directive is present. |
| `http2_proxy` | HTTP/2 is enabled and `proxy_pass` is used. |
| `scgi_uwsgi` | `scgi_pass` or `uwsgi_pass` is present. |
| `ocsp` | `ssl_stapling on` is present. |
| `dav` | `dav_methods` is enabled. |
| `mp4` | Any `mp4` directive is present. |
| `resolver` | A `resolver` directive is present. |
| `auth_http` | An `auth_http` directive is present. |
| `range` | Always; the range filter is core. |

Advisory data is current as of **2026-11-20** and is reviewed against the
[nginx security advisories](https://nginx.org/en/security_advisories.html).
To add an advisory, append a row to `CVE_DATA` in `n2rpg.sh` and add a
test in `tests/run.sh`.
