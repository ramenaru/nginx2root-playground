# nginx2root

Audit nginx for HTTP/2 weaknesses and nginx to root privilege paths.

`nginx2root` is a single-file, read-only Bash auditor. It reads the configuration that nginx actually loads, checks local permissions and processes, and optionally probes the live TLS listener. It runs on a VPS, a home server, or a laptop.

It does not exploit anything, write to nginx, or change the configuration. Each finding includes a fix and a reference.

## Features

- Reads the loaded configuration through `nginx -T`, with a direct file read fallback.
- Checks HTTP/2 setup, ALPN, h2c, stream limits, and Rapid Reset exposure.
- Checks TLS protocols, ciphers, HSTS, certificates, private keys, and OCSP.
- Checks nginx to root paths: root workers, writable configuration, binary, web root, includes, capabilities, and systemd.
- Checks configuration flaws: alias traversal, dotfiles, public `stub_status`, WebDAV, dynamic `proxy_pass`, and more.
- Includes a feature-gated CVE table with stable and mainline version matching.
- Supports offline dumps, JSON output, severity filters, and CI exit codes.
- Needs Bash and coreutils. `openssl`, `curl`, `ss`, and `capsh` add detail when present.

## Quick start

```bash
git clone https://github.com/OWNER/nginx2root.git
cd nginx2root
sudo ./nginx2root.sh
```

Or install it:

```bash
sudo ./install.sh
sudo nginx2root
```

## Examples

```bash
sudo nginx2root
sudo nginx2root --fail-on medium
sudo nginx2root --format json > audit.json
sudo nginx2root --only H2,TLS
nginx2root --dump nginx-T.txt --nginx-version 1.31.9 --no-live
```

Run `nginx2root --help` for all options.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage or environment error |
| 3 | Could not read or parse the configuration |

## Checks

There are 110 checks: 78 configuration and runtime checks plus 32 CVE checks.

| Prefix | Area |
| --- | --- |
| `ENV` | Environment and configuration syntax |
| `H2` | HTTP/2 |
| `TLS` | TLS |
| `ROOT` | nginx to root privilege paths |
| `CFG` | Configuration flaws |
| `NET` | Listeners and live headers |
| `CVE` | Feature-gated advisories |

See [docs/checks.md](docs/checks.md) for the full catalog.

## JSON output

```json
{
  "tool": "nginx2root",
  "version": "1.0.0",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 4,
    "findings": 5,
    "exit_code": 1
  },
  "findings": [
    {
      "id": "TLS-001",
      "severity": "high",
      "status": "fail",
      "title": "legacy TLS protocols enabled"
    }
  ]
}
```

The JSON output includes passing and skipped checks. Filter on `status` if you only want problems.

## Requirements

- Linux
- Bash 4.4 or newer
- coreutils
- `openssl` for certificate and live TLS checks
- `curl` for live header checks
- `ss` or `netstat` for listener checks
- root for the full permission and process audit

Without root, the tool still parses the configuration and runs most checks.

## Safety

The audit is read-only. Live probes connect only to `--host` and `--port`, which default to `127.0.0.1:443`. Do not run it against hosts you do not own.

## Development

```bash
make lint
make test
make integration
```

The fixture tests do not need root. The integration test uses Docker and a real nginx image.

## License

MIT. See [LICENSE](LICENSE).
