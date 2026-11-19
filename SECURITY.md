# Security policy

## Scope

nginx2root is a read-only auditor. Security reports should cover:

- Incorrect or dangerous findings (false negatives) in the tool.
- False positives that could cause an operator to make a harmful change.
- Command injection or path traversal through nginx configuration values.
- Unsafe handling of `--host`, `--dump`, includes, or certificate paths.
- Privilege issues in `install.sh`.

The tool intentionally does not exploit nginx. Reports asking for exploit code
are out of scope.

## Reporting

Please do not open a public issue for a vulnerability in nginx2root itself.
Use GitHub's private vulnerability reporting for the repository, or contact the
maintainer listed in the repository profile.

Include:

- Affected version/commit.
- A minimal reproduction, ideally with a config fixture.
- The expected and actual behavior.
- Any suggested fix.

## Supported versions

Only the latest release receives security fixes. Update to the latest `main`
before reporting.

## Advisories

The built-in `CVE_DATA` table is a convenience, not a substitute for your
distribution's security tracker. Always verify against
<https://nginx.org/en/security_advisories.html> and your OS vendor.
