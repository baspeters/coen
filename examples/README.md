# Coen examples

Example configurations for each setup variant and config option. Each folder has
a sample `edge.yaml` and `agent.yaml` (plus `nginx.conf` where relevant) and a
`README.md` explaining what it shows.

The configs are meant to be copied and adapted, not run as-is: paths like
`/etc/coen/pki/ca.crt` and the `REPLACE_WITH_..._FINGERPRINT` placeholders need
real values for your hosts. Generate PKI and read fingerprints with `coen cert`,
and validate a config with `coen doctor`.

Host ownership is edge-authoritative: the edge maps each host pattern to the
agent (by client-cert fingerprint) that owns it, and the fingerprint allowlist is
derived from the routes. An agent maps the same host patterns to its local
backends.

| Example | Setup | Shows |
|---------|-------|-------|
| [01-standalone-single-host](01-standalone-single-host/) | standalone (edge terminates TLS) | the one-host tunnel |
| [02-proxied-nginx](02-proxied-nginx/) | proxied (nginx terminates TLS) | coen behind an existing nginx vhost |
| [03-multi-route-one-agent](03-multi-route-one-agent/) | standalone | one agent fronting several hosts and backends |
| [04-multi-agent-host-based](04-multi-agent-host-based/) | proxied | two agents, each owning distinct hosts, via `edge.d/` drop-ins |
| [05-wildcard-and-default](05-wildcard-and-default/) | standalone | `*.example.com` wildcard plus `*` catch-all |
| [06-hardening-and-limits](06-hardening-and-limits/) | standalone | connection caps, idle deadline, per-route caps, draining |
| [07-proxied-multi-host-tls](07-proxied-multi-host-tls/) | proxied | nginx SNI and per-host certs in front of a multi-agent edge |

## Route matching

Precedence is exact, then wildcard (`*.suffix`), then default (`*`). A request
whose `Host` matches no route gets a `404` from the edge; a matched route whose
agent is offline gets a `502`; a connection over a cap gets a `503`.

## Config layout: inline or `.d` drop-ins

Routes may live inline under `routes:` in the base file, or in a `<name>.d/`
directory next to it (`edge.yaml` uses `edge.d/`), or both. Drop-in files are
routes-only fragments (`routes: [ ... ]`), merged in sorted filename order. Small
setups use one file; setups with several agents or config management drop a file
per owner.
