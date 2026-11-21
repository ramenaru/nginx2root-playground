# nginx2root-playground

Audit nginx for HTTP/2 weaknesses and nginx to root privilege paths.

`n2rpg` is a single-file, read-only Bash auditor. The name is short for nginx2root-playground. It reads the configuration that nginx actually loads, checks local permissions and processes, and optionally probes the live TLS listener. It runs on a VPS, a home server, or a laptop.

It does not exploit anything, write to nginx, or change the configuration. Each finding includes a fix and a reference.

## Features

- Reads the loaded configuration through `nginx -T`, with a direct file read fallback.
- Checks HTTP/2 setup, ALPN, h2c, stream limits, and Rapid Reset exposure.
- Checks TLS protocols, ciphers, HSTS, certificates, private keys, and OCSP.
- Checks nginx to root paths: root workers, writable configuration, binary, web root, includes, capabilities, and systemd.
- Checks configuration flaws: alias traversal, dotfiles, public `stub_status`, WebDAV, dynamic `proxy_pass`, and more.
- Includes a feature-gated CVE table with stable and mainline version matching.
- Includes a Docker lab with a vulnerable nginx 1.24 target and a hardened current nginx target.
- Supports offline dumps, JSON, SARIF, suppressions, severity filters, and CI exit codes.
- Ships a JSON schema and a composite GitHub Action wrapper.
- Needs Bash and coreutils. `openssl`, `curl`, `ss`, and `capsh` add detail when present.

## Quick start

```bash
git clone https://github.com/ramenaru/nginx2root-playground.git
cd nginx2root-playground
sudo ./n2rpg.sh
```

Or install it:

```bash
sudo ./install.sh
sudo n2rpg
```

The installer also adds `nginx2root-playground` as an alias.

## Examples

```bash
sudo n2rpg
sudo n2rpg --fail-on medium
sudo n2rpg --format json > audit.json
sudo n2rpg --only H2,TLS
n2rpg --dump nginx-T.txt --nginx-version 1.31.9 --no-live
```

Run `n2rpg --help` for all options.

## Suppressions and baselines

Suppress accepted findings with a text file:

```text
CFG-003|/etc/nginx/conf.d/status.conf|internal only|2027-01-01
ROOT-002|*|container root|
```

Fields are check ID, detail match, reason, and optional expiry date. `*` matches every finding for the check. Expired entries are ignored.

```bash
sudo n2rpg --suppressions n2rpg.suppressions
sudo n2rpg --suppressions n2rpg.suppressions --show-suppressed
```

Write a baseline from the current findings:

```bash
n2rpg --dump nginx-T.txt --write-baseline n2rpg.baseline
n2rpg --dump nginx-T.txt --suppressions n2rpg.baseline
```

The baseline file uses the same format. Suppressed findings do not affect the exit code.

## Lab

The repo includes a small Docker lab with two nginx targets:

- `vulnerable` runs nginx 1.24 with a deliberately broken configuration.
- `hardened` runs the current nginx with a tight configuration.

Start it:

```bash
./lab/run.sh
```

Then audit both targets:

```bash
./lab/audit.sh
```

Or run one by hand:

```bash
docker compose exec vulnerable n2rpg --no-color
docker compose exec hardened n2rpg --no-color
```

| Target | HTTP | HTTPS |
| --- | --- | --- |
| vulnerable | http://localhost:8080 | https://localhost:8443 |
| hardened | http://localhost:8081 | https://localhost:8444 |

The vulnerable target also exposes h2c on http://localhost:8082.

The lab walkthrough and exercises are in [lab/README.md](lab/README.md).

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

## JSON and SARIF

`--format json` emits a versioned report that matches [docs/n2rpg.schema.json](docs/n2rpg.schema.json). `--format sarif` emits SARIF 2.1.0 for code scanning.

```json
{
  "tool": "n2rpg",
  "version": "1.1.0",
  "schema_version": "1.1",
  "generated_at": "2026-11-21T00:00:00Z",
  "target": {
    "config": "/etc/nginx/nginx.conf",
    "nginx_version": "1.31.9",
    "mode": "live",
    "probe": "127.0.0.1:443"
  },
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 4,
    "passed": 2,
    "skipped": 6,
    "suppressed": 0,
    "findings": 5,
    "exit_code": 1
  },
  "findings": [
    {
      "id": "TLS-001",
      "severity": "high",
      "status": "fail",
      "title": "legacy TLS protocols enabled",
      "detail": "server[1] enables legacy TLS: TLSv1 TLSv1.1",
      "fix": "Disable TLSv1.0/1.1 in ssl_protocols.",
      "ref": "",
      "suppressed": false
    }
  ]
}
```

The JSON output includes passing and skipped checks. Suppressed findings remain in the array with `suppressed: true`, and the summary counts exclude them. Filter on `status` if you only want problems.

```bash
sudo n2rpg --format json > audit.json
sudo n2rpg --format sarif > n2rpg.sarif
```

## GitHub Action

The repository is a composite action. Run it after checkout:

```yaml
- uses: actions/checkout@v4
- uses: ramenaru/nginx2root-playground@1.1.0
  with:
    dump: nginx-T.txt
    nginx-version: "1.31.9"
    no-live: "true"
    fail-on: high
```

For SARIF and code scanning:

```yaml
- uses: actions/checkout@v4
- id: audit
  uses: ramenaru/nginx2root-playground@1.1.0
  continue-on-error: true
  with:
    dump: nginx-T.txt
    nginx-version: "1.31.9"
    no-live: "true"
    format: sarif
    output: n2rpg.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: n2rpg.sarif
- if: steps.audit.outputs.exit-code != '0'
  run: exit 1
```

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

The lab containers are intentionally vulnerable and only for local testing. Do not expose them to the internet.

## Development

```bash
make lint
make test
make integration
make lab
make lab-audit
make lab-stop
```

The fixture tests do not need root. The integration test uses Docker and a real nginx image. The lab builds two nginx images and audits both targets. CI also runs the action wrapper. CodeQL scans the action and workflows. Dependabot keeps the actions and Docker images current.

## License

MIT. See [LICENSE](LICENSE).

---

(Ο_Ο) - nginx2root-playground by ramenaru
