# 01. Standalone, single host

A one-host tunnel: the edge terminates public TLS on `:443` itself and forwards a
single hostname to one agent, which hands traffic to a local service.

```
client --HTTPS--> edge :443 (terminates TLS) --mTLS--> agent --> 127.0.0.1:8080
                  app.example.com
```

## Prerequisites

- A public DNS record `app.example.com` pointing at the edge host.
- A TLS certificate and key for `app.example.com` at `ingress.tls.cert` and
  `.key` (from any CA the public trusts; ACME automation is on the roadmap).
- A coen PKI (CA plus edge and agent keypairs), created with `coen cert`.

## Wire it up

1. On the edge and agent hosts, create the PKI and note the agent fingerprint
   (`coen cert agent` prints it). Put that fingerprint into `edge.yaml` under
   `routes[0].agent_fingerprint`.
2. Copy `edge.yaml` to the edge host (`/etc/coen/edge.yaml`) and `agent.yaml` to
   the private host (`/etc/coen/agent.yaml`); fix the paths and `edge.address`.
3. Run `coen doctor --role edge` and `coen doctor --role agent` to preflight.
4. Run `coen edge` and `coen agent` (or the systemd units).

## Verify

```
curl https://app.example.com/
coen status --socket /run/coen/edge.sock
```

`coen status` lists the connected agent.
