# Coen

A lightweight, fast, secure **self-hosted tunnel** — like Cloudflare Tunnel, but
you run both ends. Coen exposes a web app on a server that isn't reachable from
the internet by routing HTTPS/WebSocket traffic through a persistent, mutually
authenticated (mTLS) tunnel initiated *outbound* from the private side.

The name is wordplay on the **Coentunnel** in the Netherlands.

## How it works

```
internet ──HTTPS──▶ coen edge (public) ──mTLS+yamux :2636──▶ coen agent (private) ──▶ local app
```

- **`coen edge`** runs on the internet-facing host and accepts public traffic
  (either terminating TLS itself, or behind nginx).
- **`coen agent`** runs on the private host, dials out to the edge on the
  signature port **`2636`** (`COEN` on a phone keypad), authenticates with a
  client certificate, and forwards traffic to the local service. It reconnects
  automatically.

Only the agent initiates connections — no inbound ports on the private side.

## Install

```bash
git clone https://github.com/baspeters/coen
cd coen
make build            # ./bin/coen
make build-linux      # ./bin/coen-linux-amd64 (deploy target)
```

## Quickstart

**1. Create the PKI (on a trusted host):**
```bash
coen cert init --dir ./pki
coen cert edge  --dir ./pki --host edge.example.com
coen cert agent --dir ./pki --name agent-1
```
Distribute `pki/ca.crt` to both hosts, `edge.crt`/`edge.key` to the edge, and
`agent.crt`/`agent.key` to the agent.

**2. Install the services:**
```bash
sudo coen install edge     # on the public host
sudo coen install agent    # on the private host
```
Edit `/etc/coen/edge.yaml` and `/etc/coen/agent.yaml`, then:
```bash
coen doctor --role edge     # or: --role agent
sudo systemctl enable --now coen-edge     # or coen-agent
```

### Standalone mode (Coen owns :443)
Set `ingress.mode: standalone` and provide `ingress.tls.cert`/`key` (your public
PEM certificate).

### Behind nginx (nginx owns :443)
Set `ingress.mode: proxied` and `ingress.listen: 127.0.0.1:8000`. Add the snippet
from `packaging/nginx/coen.conf` to your vhost.

## Diagnostics

```bash
coen doctor --role agent    # preflight: PKI, DNS, port reach, mTLS, service, clock
coen status --socket /run/coen/edge.sock          # live snapshot
coen status --socket /run/coen/agent.sock --json  # machine-readable
```
Every connectivity step is logged as a named event; a `conn_id` in the logs
correlates a single request across both the edge and the agent. Change the log
level at runtime with `systemctl reload coen-edge` (re-reads `log.level`).

## Security

- Tunnel is **TLS 1.3** with **mutual certificate authentication** (Ed25519 CA).
  There is no shared secret in any config file — add/remove agents by
  issuing/removing certificates.
- Optional certificate **fingerprint pinning** (`edge_fingerprint`,
  `allowed_agent_fingerprints`).

## License

MIT — see [LICENSE](LICENSE).
