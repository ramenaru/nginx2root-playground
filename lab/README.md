# lab

this is a small nginx security lab. it runs two containers:

- `vulnerable` is nginx 1.24 with a lot of bad settings.
- `hardened` is the current nginx with a tighter config.

## run

```bash
./lab/run.sh
```

this builds both images and starts them.

| target | http | https |
| --- | --- | --- |
| vulnerable | http://localhost:8080 | https://localhost:8443 |
| hardened | http://localhost:8081 | https://localhost:8444 |

the vulnerable target also has an h2c listener on http://localhost:8082.

## audit

```bash
./lab/audit.sh
```

this runs the auditor inside both containers and writes json to `lab/results/`.

you can also run one target by hand:

```bash
docker compose exec vulnerable n2rpg --no-color
docker compose exec hardened n2rpg --no-color
```

## what you should see

the vulnerable target has critical and high findings. some of them:

- workers run as root
- config and nginx binary are writable
- web root is writable
- include comes from /tmp
- legacy tls and weak ciphers
- private key is world readable
- stub_status is public
- alias traversal
- webdav write methods without auth
- dynamic proxy_pass
- old nginx version with cves

the hardened target should have no critical or high findings. it still reports some info items, like ocsp stapling being off and the self signed certificate.

## exercises

1. run `./lab/audit.sh` and compare the summaries.
2. open `lab/vulnerable/nginx.conf` and find the line behind each finding.
3. fix one thing in the vulnerable config. for example, set `user nginx;` and rerun the audit.
4. change the hardened config and see what breaks.
5. run `./n2rpg.sh --dump lab/vulnerable/nginx.conf --nginx-version 1.24.0 --no-live` to audit the file without docker.

## stop

```bash
./lab/stop.sh
```

## notes

the certificates are self signed and only for the lab. do not expose these containers to the internet.

the vulnerable image uses nginx 1.24 on purpose. some checks depend on the nginx version. for example, `listen ... http2` is deprecated on 1.25.1 and newer, so the vulnerable target does not trigger that check.
