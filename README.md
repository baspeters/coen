![Coen: a lightweight, secure, self-hosted tunnel](docs/assets/coen-banner.webp)

# Coen

[![CI](https://github.com/baspeters/coen/actions/workflows/ci.yml/badge.svg)](https://github.com/baspeters/coen/actions/workflows/ci.yml)
[![CodeQL](https://github.com/baspeters/coen/actions/workflows/codeql.yml/badge.svg)](https://github.com/baspeters/coen/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/baspeters/coen/graph/badge.svg)](https://codecov.io/gh/baspeters/coen)
[![Release](https://img.shields.io/github/v/release/baspeters/coen?sort=semver)](https://github.com/baspeters/coen/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/baspeters/coen.svg)](https://pkg.go.dev/github.com/baspeters/coen)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)

Coen is a small, self-hosted tunnel. It publishes one or more private web services to the
internet over always-on, mutually authenticated connections (one per agent). It covers the
same ground as Cloudflare Tunnel or ngrok, except you run both ends and nothing sits between
your traffic and your machines.

> Status: the tunnel core (mTLS transport, HTTP and WebSocket forwarding, reconnect,
> diagnostics), multi-agent host-based routing, load balancing across several agents per host
> with graceful handoff, HTTP/3 for clients in standalone mode, public-listener limits
> (connection caps, idle deadlines, lazy backend dial), bounded graceful draining, and an
> opt-in Prometheus `/metrics` endpoint are implemented and covered by unit and end-to-end
> tests. ACME certificates and certificate revocation are still on the [roadmap](#roadmap).
> Read the [security model](#security-model) before you expose an edge to the public internet.

## Table of contents

- [Why Coen](#why-coen)
- [Features](#features)
- [How it works](#how-it-works)
- [Key concepts](#key-concepts)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Deployment modes](#deployment-modes)
- [Examples](#examples)
- [Command overview](#command-overview)
- [Configuration reference](#configuration-reference)
- [Security model](#security-model)
- [Observability and diagnostics](#observability-and-diagnostics)
- [Running as a systemd service](#running-as-a-systemd-service)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Reporting bugs and security issues](#reporting-bugs-and-security-issues)
- [Project layout](#project-layout)
- [FAQ](#faq)
- [The name](#the-name)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Why Coen

Suppose you run a web app, an API, or a dashboard on a machine that the internet cannot reach:
it lives behind NAT, a home router, a company firewall, or a cloud security group with no
inbound rules. You want to serve it publicly over HTTPS without opening inbound ports or
handing your traffic to someone else's service.

Coen does this with two small binaries:

- An agent on the private machine dials out to a public edge that you control, and keeps one
  encrypted connection open. If it drops, the agent reconnects on its own.
- The edge, on an internet-facing host you own, accepts public HTTPS and WebSocket traffic and
  sends each request back down the tunnel to the agent, which hands it to your local service.

The private side never listens on a public port. There is no shared secret in any config
file, and no third party in the data path.

## Features

- Mutual authentication. The tunnel is TLS 1.3 with client-certificate auth and an Ed25519
  CA. You add an agent by issuing it a certificate and listing its fingerprint on the edge,
  and remove one by taking its fingerprint off the edge's routes; there is no shared password
  to leak.
- Host-based routing across many agents. One edge can front many hostnames and many agents,
  matched by their client-certificate fingerprints. Routes live inline in the config or in
  `.d` drop-in files.
- Load balancing. A hostname can be served by several agents, each with its own certificate
  or sharing one, with least-connections or round-robin balancing and automatic failover to
  the remaining agents when one goes away.
- HTTPS and WebSocket. Over TCP the edge reads the `Host` header of the first request on each
  connection to pick a route, then pipes the connection through unchanged, so `Upgrade`
  handshakes and long-lived sockets work.
- Two ingress modes. The edge can terminate TLS itself with your PEM certificate, or run
  behind an existing nginx vhost as a plain-HTTP upstream.
- HTTP/3. In standalone mode the edge can also serve clients over HTTP/3 (QUIC), and tells
  browsers about it with `Alt-Svc`. Agents need no change: each request still reaches them as
  HTTP/1.1, and connections to the service are reused across a client's requests as over
  TCP. A route can be kept off HTTP/3 for services that need TCP (Windows sign-in).
- Public-listener hardening. Global and per-route connection caps, a request-header read
  timeout, an optional idle deadline, and lazy backend dial (an agent is only reached once a
  complete request head has arrived).
- Graceful shutdown. On SIGINT or SIGTERM the edge and agent stop accepting new work and drain
  in-flight streams up to a configurable timeout before exiting. A stopping agent first asks
  the edge to take it out of its routes' pools, so new connections go to the remaining agents
  and a rolling restart loses no requests.
- Automatic reconnect. The agent retries with exponential backoff and jitter; yamux
  keepalives notice dead peers behind NAT.
- Diagnostics that actually help. Named connectivity events in the logs, a `conn_id` that ties
  a single request together across both processes, a `coen doctor` preflight, a live
  `coen status` socket, and an opt-in Prometheus `/metrics` endpoint with per-route and
  per-agent series.
- Simple to operate. One binary with subcommands, YAML config, and a `coen install` that
  writes a hardened systemd unit on Linux or a launchd job on macOS.
- Small footprint. Pure Go with a handful of third-party dependencies (`cobra`, `yamux`,
  `yaml.v3`, and `quic-go` plus `golang.org/x/net` for HTTP/3); everything else is the
  standard library.

## How it works

```mermaid
flowchart LR
    client["Browser or API client"]

    subgraph pub["Public host, internet-facing"]
        edge["coen edge, :443 ingress (TCP, and UDP for HTTP/3), :2636 tunnel"]
    end

    subgraph priv["Private host, behind NAT or firewall"]
        agent["coen agent"]
        app["Local web app 127.0.0.1:8080"]
    end

    client -->|"HTTPS / WSS"| edge
    agent ==>|"1. dials out over mTLS, TLS 1.3"| edge
    edge ==>|"2. one yamux stream per client connection"| agent
    agent -->|"plain HTTP"| app
```

Only the agent opens a connection. The edge never needs a route into the private network,
which is what lets Coen work from behind NAT without any inbound ports.

## Key concepts

- Edge: the public `coen edge` process. It terminates (or, behind nginx, receives) public
  traffic, reads the request's `Host` header, and routes it to one of the agents that own that
  hostname (fewest open streams, or round robin).
- Agent: the private `coen agent` process. It dials the edge, authenticates, and bridges each
  stream to the local service matched by the request's `Host`.
- Route: a `host` pattern paired with a target. On the edge the target is one or more agents
  (by client-certificate fingerprint); on the agent it is a local backend address. Matching is
  exact, then wildcard (`*.suffix`), then a default (`*`).
- Tunnel: each agent keeps one persistent mTLS connection to port `2636` (`COEN` on a phone
  keypad), carrying many multiplexed [yamux](https://github.com/hashicorp/yamux) streams.
- Stream and preamble: every TCP client connection becomes one stream. Over HTTP/3 a request
  takes a stream that is then kept for later requests of the same QUIC connection (see
  [HTTP/3 for clients](#http3-for-clients)). Each stream starts with a short preamble that
  carries a `conn_id`, the original client address, and the request `Host`, so a request can
  be routed by the agent and traced end to end.

### Request data flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant E as coen edge
    participant A as coen agent
    participant B as Backend app
    Note over E,A: Persistent mTLS + yamux tunnel on :2636
    C->>E: HTTPS request, TLS terminated at edge or nginx
    E->>E: Read the Host header, match a route, pick one of its agents
    E->>A: Open a yamux stream, preamble carries conn_id, client_addr, Host
    A->>B: Dial the backend that the agent maps this Host to
    C->>B: request bytes piped through the tunnel
    B->>C: response bytes piped back
```

### Agent connection lifecycle

The agent runs a connect and reconnect loop, so a dropped tunnel always recovers.

```mermaid
stateDiagram-v2
    [*] --> Dialing
    Dialing --> Handshaking: TCP connected
    Dialing --> Backoff: dial failed
    Handshaking --> Connected: mTLS and fingerprint OK
    Handshaking --> Backoff: cert or pin rejected
    Connected --> Serving: accept streams
    Serving --> Backoff: tunnel dropped
    Serving --> Draining: SIGINT or SIGTERM, the edge takes the agent out of its pools
    Draining --> [*]: in-flight streams done, or drain_timeout
    Backoff --> Dialing: wait, exp backoff and jitter
```

### Ingress modes

```mermaid
flowchart TB
    subgraph MA["Mode A: standalone, coen owns :443"]
        direction LR
        ca["Client"] -->|"HTTPS :443"| ea["coen edge terminates TLS with your PEM cert"]
        ea -->|"encrypted tunnel"| aa["agent, then local app"]
    end
    subgraph MB["Mode B: proxied, nginx owns :443"]
        direction LR
        cb["Client"] -->|"HTTPS :443"| nb["nginx terminates TLS"]
        nb -->|"plain HTTP 127.0.0.1:8000"| eb["coen edge"]
        eb -->|"encrypted tunnel"| ab["agent, then local app"]
    end
```

## Installation

Coen is a single static binary. The daemons target Linux (systemd); `coen install` also
generates a launchd job on macOS, and on other systems it prints how to run coen under that
platform's service manager. The CLI and the
`coen cert` tooling run anywhere Go does.

### From a release (prebuilt binary)

Download the archive for your OS and architecture from the
[latest release](https://github.com/baspeters/coen/releases/latest). Assets are named
`coen_<version>_<os>_<arch>.tar.gz` (linux/darwin, amd64/arm64), with a `checksums.txt`
alongside for verification. Extract and put `coen` on your PATH:

```bash
tar -xzf coen_*_linux_amd64.tar.gz coen
sudo install coen /usr/local/bin/coen
coen version
```

### Linux packages (.deb, .rpm, .apk)

Every release also ships native packages for amd64 and arm64. They install the
binary to `/usr/bin/coen`, add systemd units for both roles under
`/usr/lib/systemd/system`, create a dedicated `coen` service user, and lay down
example configs plus the `edge.d/` and `agent.d/` route drop-in directories in
`/etc/coen` (configs preserved across upgrades). Download the file
for your distribution from the
[latest release](https://github.com/baspeters/coen/releases/latest):

```bash
# Debian, Ubuntu
sudo dpkg -i coen_*_linux_amd64.deb

# Fedora, RHEL, openSUSE
sudo rpm -i coen_*_linux_amd64.rpm

# Alpine
sudo apk add --allow-untrusted coen_*_linux_amd64.apk
```

The services are installed but not started. Edit the config for your role, put
the certificates under `/etc/coen` (see [Quick start](#quick-start)), then
enable the unit:

```bash
sudo systemctl enable --now coen-edge     # or coen-agent
```

### With `go install`

Requires Go 1.26 or newer:

```bash
go install github.com/baspeters/coen/cmd/coen@latest
```

### From source

```bash
git clone https://github.com/baspeters/coen
cd coen
make build          # produces ./bin/coen
make build-linux    # produces ./bin/coen-linux-amd64 for the server
```

## Quick start

The steps below run a full trial on one machine, with the edge, agent, and a backend all on
`127.0.0.1`. A two-host deployment is the same; only the addresses and the certificate host
change.

First, build and create the PKI. One command creates the CA, two more issue the edge and agent
certificates from it.

```bash
make build
./bin/coen cert init  --dir ./pki
./bin/coen cert edge  --dir ./pki --host 127.0.0.1     # use your public FQDN in production
./bin/coen cert agent --dir ./pki --name my-agent
```

Next, write two config files.

```yaml
# edge.yaml, the public side. Proxied mode takes plain HTTP, so no PEM is needed here.
ingress:
  mode: proxied
  listen: 127.0.0.1:8000
tunnel:
  listen: 127.0.0.1:2636
  ca:   ./pki/ca.crt
  cert: ./pki/edge.crt
  key:  ./pki/edge.key
routes:
  - host: "*"                   # catch-all for the trial (see Configuration reference)
    agent_fingerprint: "<my-agent's fingerprint>"   # printed by `coen cert agent`
admin:
  socket: /tmp/coen-edge.sock
```

```yaml
# agent.yaml, the private side.
edge:
  address: 127.0.0.1:2636
  ca:   ./pki/ca.crt
  cert: ./pki/agent.crt
  key:  ./pki/agent.key
routes:
  - host: "*"
    service: 127.0.0.1:9000     # your local app
admin:
  socket: /tmp/coen-agent.sock
```

Start a backend, the edge, and the agent, either in three terminals or in the background.

```bash
python3 -m http.server 9000            # stand-in for your private app
./bin/coen edge  --config edge.yaml
./bin/coen agent --config agent.yaml
```

Check the tunnel and send a request through it.

```bash
./bin/coen status --socket /tmp/coen-edge.sock     # lists the connected agent
curl http://127.0.0.1:8000/                        # served by :9000, through the tunnel
```

Before going live, run the preflight on each host. It checks the certificates and keys, DNS,
that the listen ports (TCP, the HTTP/3 UDP port, and the metrics port) can be bound, that the
edge is reachable, a live mTLS handshake, the clock against the certificates' validity, and,
on the agent, that each route's service accepts a connection (see
[Observability and diagnostics](#observability-and-diagnostics) for the full list).

```bash
./bin/coen doctor --role edge  --config edge.yaml     # the trial above
./bin/coen doctor --role agent --config agent.yaml
coen doctor                                           # an installed host with its daemon running (role and config detected)
coen doctor --role edge                               # an installed host before starting: /etc/coen/edge.yaml
```

## Deployment modes

The tunnel side is identical either way. What changes is how the edge takes in public traffic.

### Mode A: standalone, Coen terminates TLS

Set `ingress.mode: standalone`, bind `:443`, and point Coen at your PEM certificate.

```yaml
ingress:
  mode: standalone
  listen: ":443"
  tls:
    cert: /etc/coen/certs/public.crt   # for example, from Let's Encrypt or certbot
    key:  /etc/coen/certs/public.key
```

Open TCP 443 to clients and TCP 2636 to your agents (and UDP 443 too with
[HTTP/3](#http3-for-clients)). The `coen` service user must be able to read both PEM files;
`/etc/letsencrypt/live` is root-only by default, so copy them to `/etc/coen/certs`, which the
packages create. The edge reads the certificate once, at startup: after a renewal, restart
it (for example from a certbot deploy hook running `systemctl restart coen-edge`). Agents
reconnect on their own, and the drain lets requests in flight finish.

### Mode B: behind nginx, nginx terminates TLS

Set `ingress.mode: proxied` and `ingress.listen: 127.0.0.1:8000`. nginx keeps `:443` and its
certificate. Add the snippet from [`packaging/nginx/coen.conf`](packaging/nginx/coen.conf) to
your vhost. It includes the `map` block that WebSocket upgrades need.

```nginx
# In the http { } context:
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

# In your server { } vhost:
location / {
    proxy_pass http://127.0.0.1:8000;   # coen edge in proxied mode
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Only the tunnel port (`2636`) needs to be reachable by the agent. nginx keeps `:443`, and the
mTLS tunnel stays end to end, since nginx never sees the tunnel's certificates.

Client addresses: Coen passes the request through unchanged and adds no forwarding headers of
its own. In proxied mode the `client_addr` in Coen's logs is nginx's address, and your service
learns the client's IP from nginx's `X-Forwarded-For`. In standalone mode (TCP or HTTP/3) the
client's address appears only in Coen's logs.

### HTTP/3 for clients

In standalone mode the edge can serve HTTP/3 (QUIC over UDP) next to HTTPS over TCP:

```yaml
ingress:
  mode: standalone
  listen: ":443"
  tls: { cert: /etc/coen/certs/public.crt, key: /etc/coen/certs/public.key }
  http3:
    enabled: true        # UDP :443, the same port number as listen
    # listen: ":8443"    # a different UDP address, if needed
    # alt_svc: auto      # auto (default), off, or a literal Alt-Svc value
```

- **Open UDP 443** in the firewall as well as TCP 443. `coen doctor` checks that the UDP
  port can be bound, and on Linux whether the kernel's UDP buffers are as large as QUIC asks
  for (raise `net.core.rmem_max` and `net.core.wmem_max` to at least 7340032 for full speed).
- **Agents are unchanged.** The edge terminates HTTP/3 and sends each request through the
  tunnel as an HTTP/1.1 request, as one arriving over TCP. A request body of unknown length
  goes as `Transfer-Encoding: chunked`.
- **Connections to the service are reused,** as over TCP: once a response has ended, its
  tunnel stream (one connection to the service) carries the next request of the same HTTP/3
  connection, so a request does not wait for a new stream and a new connection to the
  service. Up to 32 per HTTP/3 connection are kept, for as long as the HTTP/3 connection
  stays open (at most `ingress.idle_timeout` without a request, `30s` when unset); one is
  never shared
  between HTTP/3 connections, so a service that ties state to its connection only ever sees
  one client's requests on it. A response with `Connection: close` (or without a length)
  ends its stream. If the service closes a kept connection just as a request goes out and
  nothing comes back, the edge sends the request again on a fresh one. Only requests that may
  be sent twice take a kept connection: `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`, or
  one with an `Idempotency-Key` (or `X-Idempotency-Key`) header, without a body or with one of
  up to 64 KiB. Others, such as a `POST`, go on a fresh connection (which is then kept), so
  they are never sent twice. A route's kept connections also give way to TCP clients when the
  route is full. The edge picks an agent each time it opens a connection to the service, so
  with [load balancing](#load-balancing) one HTTP/3 connection's requests can reach different
  agents; a kept connection stays with its agent.
- **How clients find it.** Browsers first connect over TCP; the edge adds
  `Alt-Svc: h3=":443"; ma=86400` to the first response on each connection, unless the service
  sets its own `Alt-Svc`. `alt_svc: off` leaves responses alone (except on hosts kept off
  HTTP/3, below), and any other value is sent as given. The port in `auto` is the UDP port
  HTTP/3 is served on. A DNS `HTTPS` record lets a browser use HTTP/3 from the first request:
  `app.example.com. 300 IN HTTPS 1 . alpn="h3"`.
- **Limits.** `ingress.max_connections` counts each QUIC connection as one, together with the
  TCP connections; a QUIC connection over it is closed at once with `H3_EXCESSIVE_LOAD`
  (counted as `max_connections`) rather than answered `503`. A connection carries at most 100
  requests at once (the client queues the rest). A route's `max_connections` counts connections to the service, kept ones included;
  a request that finds it full takes the slot of a kept one, or waits up to
  `ingress.read_header_timeout` for one, so the service never sees more than that many
  either way.
- **Timeouts.** `ingress.read_header_timeout` bounds the QUIC handshake (no packet for that
  long, or twice that in all) and the wait for a new
  connection's first request. A connection with no request in progress closes after
  `ingress.idle_timeout` (`30s` when unset, since QUIC always needs an idle limit), and its
  kept connections to the service with it. Keep-alives hold a connection through a quiet
  response such as server-sent events. When `ingress.idle_timeout` is set, a request with no
  response within it gets `504`. A large `idle_timeout` (for quiet WebSockets) therefore also
  keeps idle HTTP/3 connections, and up to 32 connections to the service each, open that long.
  On shutdown, new connections are refused at once, kept connections to services are closed,
  and requests in flight finish within `drain_timeout`.
- **WebSockets** work over both. A browser may open one over HTTP/3 (RFC 9220, extended
  `CONNECT`); the edge turns it into the usual HTTP/1.1 `Upgrade` towards the agent, so the
  service sees an ordinary WebSocket handshake. Other `CONNECT` requests get `501`. 0-RTT is
  off, so a captured request cannot be replayed by anyone else.
- **Keeping a host off HTTP/3.** Windows sign-in (NTLM, Negotiate/Kerberos) authenticates the
  TCP connection, which HTTP/3 (like HTTP/2) cannot carry; over TCP it works, since each client
  connection reaches the service as one connection. Over HTTP/3 it may seem to work, when the
  sign-in's requests happen to reuse one connection to the service, and then fail when other
  requests run alongside it. `http3: false` on a route keeps its hosts on TCP:
  - The first TCP response on each connection gets `Alt-Svc: clear` in place of any `Alt-Svc`
    the service sets, whatever `alt_svc` says, so a browser forgets HTTP/3 for the host.
    Later responses on the connection, and a head the edge cannot read (bare LF line endings,
    or over its size limit), pass unchanged, so a service should not advertise HTTP/3 itself
    (behind coen it cannot serve it anyway); if it does, a browser only spends a refused
    handshake before using TCP again.
  - An HTTP/3 handshake for the host is refused, so the browser falls back to TCP. A
    handshake without a server name (a client that dialled an IP address) is judged by the
    default `*` route.
  - A request for the host on an HTTP/3 connection made for another host (browsers reuse one
    for every host its certificate covers) gets `421 Misdirected Request`, which tells the
    browser to retry on a new connection.

  Requests answered `421` count as `coen_ingress_rejected_total{reason="http3_off"}`; refused
  handshakes are only logged (at `debug`), since they come before any request. Leave such hosts
  out of DNS `HTTPS` records. The setting needs `standalone` mode; behind nginx, keep the host
  out of nginx's HTTP/3 instead.
- **Behind nginx (proxied mode)**, let nginx serve HTTP/3 instead: nginx 1.25 or newer with
  `listen 443 quic reuseport;`, `http3 on;` and `add_header Alt-Svc 'h3=":443"; ma=86400';` in
  the vhost. nginx forwards to the edge over plain HTTP as before, so the edge needs no
  `http3` settings.

### Agents behind restrictive networks

An agent dials the edge's tunnel port, `2636` by default. Where the agent's network only lets
connections out to port 443, or only through an HTTP proxy, two settings get it through. Both
keep the tunnel's end-to-end mTLS exactly as it is: nothing between the agent and the edge
sees inside it.

**The tunnel on the ingress port (standalone mode).** With `tunnel.share_ingress: true` the
edge also takes agents on `ingress.listen`, usually `:443`:

```yaml
# edge.yaml
ingress:
  mode: standalone
  listen: ":443"
  tls: { cert: /etc/coen/certs/public.crt, key: /etc/coen/certs/public.key }
tunnel:
  share_ingress: true       # agents may connect to :443 too
  # listen: ":2636"         # optional now; keep it for agents older than v0.4.0
  ca:   /etc/coen/pki/ca.crt
  cert: /etc/coen/pki/edge.crt
  key:  /etc/coen/pki/edge.key
```

```yaml
# agent.yaml
edge:
  address: edge.example.com:443
```

- **How it tells them apart.** An agent's TLS handshake offers the protocol `coen/2` (ALPN);
  a browser's never does. The edge reads that offer before it chooses a certificate: an agent
  gets the tunnel's mTLS handshake (the edge's tunnel certificate, a client certificate
  required), and everyone else the public certificate, as before. Nothing else changes: the
  agent is accepted, counted and logged exactly as on the tunnel port.
- **Agents from v0.4.0 on.** Older agents offer no ALPN, so on a shared port they get the
  public certificate and fail to verify it. Keep `tunnel.listen` for them until they are
  upgraded; both ways in work at once.
- **The edge's tunnel certificate** must name the host in the agent's `edge.address`, as
  always (`coen cert edge --host edge.example.com`); the public and tunnel certificates can
  name the same host.
- **Limits.** An agent's connection counts against `ingress.max_connections` only during its
  handshake, and is never answered with the `503` page: at the cap, the edge still completes
  an agent's handshake and takes it. A client that offers `coen/2` without a valid client
  certificate is a rejected tunnel handshake (`coen_tunnel_handshakes_total{result="rejected"}`),
  not a bad ingress request.
- **Proxied mode** cannot share: nginx terminates TLS, so the edge never sees the agent's
  handshake. Keep `tunnel.listen` reachable there (the config rejects `share_ingress` in
  proxied mode).

**Through an HTTP proxy.** With `edge.proxy` the agent reaches the edge through an HTTP proxy,
with `CONNECT`:

```yaml
# agent.yaml
edge:
  address: edge.example.com:443        # most proxies allow CONNECT only to port 443
  proxy: http://user:password@proxy.corp.example:3128   # or https://, or no credentials
```

- The agent asks the proxy for a tunnel to `edge.address` and runs its mTLS through it; the
  proxy resolves the edge's name. Basic credentials come from the URL (percent-encode special
  characters); logs show them as `xxxxx`. Keep `agent.yaml` readable only by root and `coen`,
  as the packages install it.
- `https://` connects to the proxy over TLS, verified against the system's trusted CAs.
- Many proxies (squid's default `SSL_ports`) allow `CONNECT` only to port 443, so pair a proxy
  with an edge that shares its ingress, as above.
- `coen doctor` on the agent checks through the proxy too: it resolves the proxy's name
  instead of the edge's, and a refused `CONNECT` shows the proxy's answer (for example `407`
  for missing credentials, `403` for a port it does not allow).
- A proxy that intercepts TLS (decrypts and re-encrypts it) cannot carry the tunnel: the edge
  sees the proxy's certificate instead of the agent's. Such networks need a transport over
  WebSockets, which is on the [roadmap](#roadmap).

## Examples

The [`examples/`](examples/) directory has an example configuration for every setup variant and
config option, each with its own README:

| Example | Shows |
| --- | --- |
| [standalone, single host](examples/01-standalone-single-host/) | the smallest one-host tunnel |
| [proxied behind nginx](examples/02-proxied-nginx/) | coen behind an existing nginx vhost |
| [multiple routes, one agent](examples/03-multi-route-one-agent/) | one agent fronting several hosts/backends |
| [multiple agents, host-based](examples/04-multi-agent-host-based/) | two agents owning distinct hosts, via `edge.d/` drop-ins |
| [wildcard and default](examples/05-wildcard-and-default/) | `*.example.com` + `*` catch-all matching |
| [hardening and limits](examples/06-hardening-and-limits/) | connection caps, idle deadline, per-route caps, draining |
| [proxied multi-host TLS](examples/07-proxied-multi-host-tls/) | nginx SNI + per-host certs in front of a multi-agent edge |
| [Prometheus metrics](examples/08-prometheus-metrics/) | the opt-in `/metrics` endpoint on edge and agent, with a scrape config and alerts |
| [load balancing](examples/09-load-balancing/) | several agents per host, by separate or shared certificates, with failover and handoff |
| [HTTP/3](examples/10-http3/) | HTTP/3 (QUIC) for clients, advertised with `Alt-Svc`, and a host kept off it with `http3: false` |
| [agents on port 443](examples/11-agents-on-443/) | agents connecting to the ingress port, directly or through an HTTP proxy |

## Command overview

Everything lives under one binary, invoked as `coen <command>`.

| Command | What it does |
| --- | --- |
| `coen edge` | Run the public edge (ingress plus the mTLS tunnel server). |
| `coen agent` | Run the private agent (dials the edge, forwards to a local service). |
| `coen cert init` | Create a new Coen CA (`ca.crt`, `ca.key`). |
| `coen cert edge` | Issue the edge (server) certificate, signed by the CA. |
| `coen cert agent` | Issue an agent (client) certificate. |
| `coen doctor` | Role-aware preflight checks with pass/fail results and remediation hints. Auto-detects the role from the running daemon; pass `--role` for a preflight before the daemon is started. `--json` for machine-readable output. |
| `coen status` | Live snapshot from a running daemon over its admin socket. Auto-detects which daemon is running; `--socket`, `--config` (read the socket from a config file) or `--role` override it. `--json` for scripts. |
| `coen install` | Write a service definition (systemd unit on Linux, launchd plist on macOS) and an example config for a role. An existing service definition is kept unless `--force`; an existing config is never overwritten. |
| `coen version` | Print the version. |
| `coen completion <shell>` | Print a shell completion script (bash, zsh, fish, powershell). |

Flags and examples:

```bash
# PKI. Default --dir is /etc/coen/pki; --force overwrites an existing CA.
coen cert init  --dir /etc/coen/pki
coen cert edge  --dir /etc/coen/pki --host edge.example.com   # FQDN or IP goes into the cert SAN
coen cert agent --dir /etc/coen/pki --name laptop-agent       # --name becomes the certificate CN

# Daemons. Default --config is /etc/coen/<role>.yaml.
coen edge  --config /etc/coen/edge.yaml
coen agent --config /etc/coen/agent.yaml

# Diagnostics. With a daemon running, both auto-detect the role from the host's
# process table, so on each host `coen doctor` and `coen status` need no flags.
coen doctor                                                   # auto-detects role; exits non-zero if any check fails
coen doctor --role edge  --config /etc/coen/edge.yaml         # preflight before the daemon is started
coen status                                                   # auto-detects the running daemon
coen status --socket /run/coen/edge.sock                      # or point at a socket; add --json for scripts

# Packaging.
coen install edge  --unit-dir /etc/systemd/system --config-dir /etc/coen --bin /usr/local/bin/coen
coen install edge  --force                                    # replace an existing unit; the config is never overwritten
```

Sending `SIGHUP`, or running `systemctl reload`, re-reads a running daemon's config and
hot-applies the `log.level` without a restart. Other changes (routes, listeners, caps,
timeouts, fingerprints) are read at startup and take effect only when the process restarts.

## Configuration reference

### The config system

- **One file per role.** The edge reads `edge.yaml`, the agent reads `agent.yaml`. The
  defaults are `/etc/coen/edge.yaml` and `/etc/coen/agent.yaml`; override either with
  `--config <path>`.
- **Format.** YAML (`gopkg.in/yaml.v3`). Unknown keys are rejected in both the base file and
  drop-in files, so a misspelled field fails at startup instead of being silently ignored.
- **Durations** are Go duration strings: `500ms`, `10s`, `2m`, `1h`. Every field whose name
  ends in `_timeout` or `_backoff` takes one.
- **Validation at startup.** The daemon refuses to start on an invalid config and prints the
  offending field. It checks the ingress mode, the required paths and addresses, that there is
  at least one route, that every `host` pattern is well formed, and that no host is defined
  twice. On the edge it also checks each route's agent fields (exactly one of
  `agent_fingerprint` and `agent_fingerprints`, no empty or repeated entry, a known
  `balance`), that `allow_shared_cert` is set alike on every route that names a fingerprint,
  the `ingress.http3` settings (only when `enabled`: standalone mode, a valid UDP address, a
  single-line `alt_svc`), that `http3: false` is not used in `proxied` mode, and that
  `tunnel.share_ingress` is only used in `standalone` mode (with it, `tunnel.listen` is
  optional). On the agent, `edge.proxy` must be an `http://` or `https://` URL naming a host,
  with nothing after it but optional credentials. On both roles
  `metrics.listen` must be a valid `host:port` that does not overlap the daemon's own
  listeners (edge) or a route's `service` (agent); every agent route needs a `service`.
  Fingerprints are compared exactly; their format is only checked by `coen doctor`, so a
  placeholder left in a route starts fine and then refuses every agent. `coen doctor` goes
  further at runtime (file presence, certificate validity, DNS, reachability, a live mTLS
  handshake, clock skew, and each route's backend).
- **Reload.** `SIGHUP` (or `systemctl reload`) re-reads the file and hot-applies `log.level`
  only. Routes, listeners, caps, timeouts, and fingerprints are read at startup and change
  only on restart.
- **Drop-in route files (`.d`).** Routes may live inline under `routes:` and/or in a
  `<name>.d/` directory next to the config file: `edge.yaml` uses `edge.d/`, `agent.yaml` uses
  `agent.d/`. Each drop-in is a routes-only fragment (a top-level `routes:` list and nothing
  else; any other key is an error). Regular files ending in `.yaml` directly in that directory
  (not `.yml`, and not subdirectories) are read in sorted filename order, their routes
  appended to the inline `routes`, and the merged set validated together. The directory is
  named after the config file: `--config /x/foo.yaml` uses `/x/foo.d/`. A host defined twice, whether across two drop-ins or between
  a drop-in and the base file, is a load error that names both sources. The directory is
  optional; when absent, only the inline `routes` are used. Drop-ins suit one file per
  agent or team, and config-managed deployments.

  ```
  /etc/coen/
    edge.yaml          # base config, may carry inline routes
    edge.d/            # optional; merged in sorted order
      team-a.yaml      #   routes: [ { host: app.example.com, agent_fingerprint: "..." } ]
      team-b.yaml      #   routes: [ { host: api.example.com, agent_fingerprint: "..." } ]
  ```

### Log formats

- `text` (logfmt) and `json` are machine-readable and self-contained (each line
  carries its own timestamp and level).
- `journal` is for systemd/journald: it omits the timestamp (journald adds one),
  encodes the level as a syslog priority so `journalctl -p` filters work, and
  renders each event as a short phrase followed by comma-separated fields, for
  example `stream closed, conn_id=..., host=tweake.rs, bytes_in=355`. In this
  format the dotted event ids (`stream.closed`) render as words (`stream closed`);
  `text` and `json` keep the dotted id.
- When `log.format` is unset, coen autodetects: `journal` when its output is
  connected to the journal, otherwise `text`. Set the value explicitly to force
  one (for example `text` to debug a service in a terminal).

### Edge configuration (`edge.yaml`)

```yaml
ingress:
  mode: standalone          # standalone or proxied
  listen: ":443"            # standalone; use "127.0.0.1:8000" behind nginx
  tls:                      # ignored in proxied mode, where nginx owns the cert
    cert: /etc/coen/certs/public.crt
    key:  /etc/coen/certs/public.key
  max_connections: 0        # global cap on concurrent ingress conns; 0 = unlimited
  read_header_timeout: 10s  # bound on reading the HTTP request head; default 10s
  idle_timeout: 0           # rolling idle deadline while streaming; 0 = disabled
  http3:                    # optional; standalone mode only
    enabled: false          # true: also serve HTTP/3 (QUIC) on UDP
    # listen: ":443"        # UDP address; default: ingress.listen
    # alt_svc: auto         # auto, off, or a literal Alt-Svc value
tunnel:
  listen: ":2636"           # mTLS server the agent dials
  # share_ingress: false    # true: agents may also connect to ingress.listen (standalone)
  ca:   /etc/coen/pki/ca.crt
  cert: /etc/coen/pki/edge.crt
  key:  /etc/coen/pki/edge.key
routes:                     # host -> owning agent(s) (by client-cert fingerprint)
  - host: app.example.com   # exact, "*.example.com" wildcard, or "*" default
    agent_fingerprint: "SHA256:..."
    max_connections: 0      # optional per-route cap; 0 = unlimited
  - host: api.example.com   # load-balanced across several agents
    agent_fingerprints: ["SHA256:...", "SHA256:..."]
    balance: least_conn     # least_conn (default) or round_robin
    allow_shared_cert: false # true: several agents may run with one certificate
    http3: true             # false: keep this host off HTTP/3 (see HTTP/3 for clients)
drain_timeout: 15s          # finish in-flight streams up to this long on shutdown
log:
  level: info               # trace, debug, info, warn, or error
  # format:                 # unset autodetects (journal under systemd, text otherwise); text|json|journal
admin:
  socket: /run/coen/edge.sock
metrics:                    # optional; unset disables the endpoint
  listen: 127.0.0.1:9464    # Prometheus GET /metrics; keep it private, it has no auth
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `ingress.mode` | string | required | `standalone` (the edge terminates public TLS) or `proxied` (nginx terminates TLS and the edge receives plain HTTP). |
| `ingress.listen` | string | required | Public ingress address, `host:port`. `:443` in standalone, `127.0.0.1:8000` behind nginx. |
| `ingress.tls.cert`, `ingress.tls.key` | path | required in `standalone` | PEM certificate and key for public TLS. Unused in `proxied` mode. |
| `ingress.max_connections` | int | `0` | Global cap on concurrent client connections, TCP and HTTP/3 (QUIC) counted together. Over it a TCP connection gets `503` and a QUIC connection is closed with `H3_EXCESSIVE_LOAD`. `0` means unlimited. |
| `ingress.read_header_timeout` | duration | `10s` | Deadline for reading a request head (slow-loris protection). Always enforced; `0` or unset falls back to the default and cannot disable it. For HTTP/3 it also bounds the QUIC handshake, the wait for a connection's first request, and how long a request waits for a slot of its route's `max_connections`. |
| `ingress.idle_timeout` | duration | `0` | Rolling idle deadline while streaming: a TCP connection with no bytes in either direction for this long is closed. `0` disables it. See the WebSocket note below. With HTTP/3 it also closes a connection with no request in progress, and is how long an idle connection to the service is kept for that client's next request (both `30s` when unset; `0` does not disable them). When set, an HTTP/3 request with no response for this long gets `504`. |
| `ingress.http3.enabled` | bool | `false` | Serve HTTP/3 (QUIC over UDP) as well; `standalone` mode only. See [HTTP/3 for clients](#http3-for-clients). The other `ingress.http3` keys are only checked when this is `true`. |
| `ingress.http3.listen` | string | `ingress.listen` | UDP address for HTTP/3, `host:port`. |
| `ingress.http3.alt_svc` | string | `auto` | `Alt-Svc` added to the first final response on each TCP connection, unless the service sent its own: `auto` sends `h3=":<UDP port>"; ma=86400`, `off` adds nothing, and any other value (a single header line) is sent as given. While HTTP/3 is enabled, routes with `http3: false` always get `Alt-Svc: clear` in place of the service's. |
| `tunnel.listen` | string | required, unless `share_ingress` | Address of the mTLS tunnel server the agents dial, e.g. `:2636`. |
| `tunnel.share_ingress` | bool | `false` | Also accept agents on `ingress.listen`, told apart from browsers by the TLS protocol they offer; `standalone` mode only. Agents from v0.4.0 on. See [Agents behind restrictive networks](#agents-behind-restrictive-networks). |
| `tunnel.ca` | path | required | CA bundle that an agent's client certificate must chain to. |
| `tunnel.cert`, `tunnel.key` | path | required | The edge's server certificate and key for the tunnel. |
| `routes` | list | at least one | Host ownership; see [Host routing](#host-routing-and-matching). May be split into `edge.d/`. |
| `routes[].host` | string | required | Match pattern: an exact host, a `*.suffix` wildcard, or `*` (default). |
| `routes[].agent_fingerprint` | string | one of the two | Fingerprint of the agent that owns this host: `SHA256:` followed by the standard base64 of the certificate's SHA-256 (44 characters), compared exactly; `coen cert agent` prints it. The set of all route fingerprints is the connection allowlist. |
| `routes[].agent_fingerprints` | list | one of the two | Several agent fingerprints for a load-balanced host; see [Load balancing](#load-balancing). Use this or `agent_fingerprint`, not both. |
| `routes[].balance` | string | `least_conn` | How connections are spread across the route's live agent sessions: `least_conn` (the session with the fewest open streams, counted across all the routes it serves, kept HTTP/3 connections included) or `round_robin`. |
| `routes[].allow_shared_cert` | bool | `false` | Let several agents run with the same certificate, each as its own session. Must be set the same way on every route that names that fingerprint. |
| `routes[].max_connections` | int | `0` | Per-route cap on concurrent connections to the service. `0` means unlimited. Over TCP each client connection holds one slot, and a connection over the cap gets `503` at once. Over HTTP/3 each open connection to the service holds one, including those kept idle for the client's next request; a request over the cap takes the slot of a kept one, or waits up to `ingress.read_header_timeout` for a slot, then gets `503`. A TCP connection can also take a kept HTTP/3 connection's slot. |
| `routes[].http3` | bool | `true` | `false` keeps the route's hosts off HTTP/3, for services with connection-based auth; see [HTTP/3 for clients](#http3-for-clients). Rejected in `proxied` mode; no effect unless `ingress.http3.enabled`. |
| `drain_timeout` | duration | `15s` | On shutdown, finish in-flight streams for up to this long before force-closing. `0` or unset uses the default (15s). |
| `log.level` | string | `info` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `log.format` | string | autodetect | `text`, `json`, or `journal`. Unset autodetects: `journal` under systemd (journald), otherwise `text`. See [Log formats](#log-formats). |
| `admin.socket` | path | (unset) | Unix socket for `coen status` and `coen doctor`'s live-tunnel check. When unset, the admin socket is disabled. A small `<socket>.lock` file next to it coordinates a restart that overlaps a draining instance and is left in place. |
| `metrics.listen` | string | (unset) | `host:port` for the Prometheus endpoint (`GET /metrics`). When unset, metrics are disabled. It has no authentication, so bind it to loopback or a private interface. Rejected if it overlaps `tunnel.listen` or `ingress.listen`. See [Prometheus metrics](#prometheus-metrics). |

### Agent configuration (`agent.yaml`)

```yaml
edge:
  address: edge.example.com:2636
  ca:   /etc/coen/pki/ca.crt
  cert: /etc/coen/pki/agent.crt
  key:  /etc/coen/pki/agent.key
  # edge_fingerprint: "SHA256:..."               # optional certificate pinning
  # proxy: http://user:password@proxy:3128       # optional: reach the edge through an HTTP proxy
routes:                     # host -> local backend service
  - host: app.example.com
    service: 127.0.0.1:8080
reconnect:
  min_backoff: 1s
  max_backoff: 30s
drain_timeout: 15s          # finish in-flight streams up to this long on shutdown
log:
  level: info
  # format:                 # unset autodetects (journal under systemd, text otherwise); text|json|journal
admin:
  socket: /run/coen/agent.sock
metrics:                    # optional; unset disables the endpoint
  listen: 127.0.0.1:9465
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `edge.address` | string | required | `host:port` of the edge tunnel. The host part must match a name in the edge's server certificate. |
| `edge.ca` | path | required | CA bundle the edge's server certificate must chain to. |
| `edge.cert`, `edge.key` | path | required | The agent's client certificate and key. |
| `edge.edge_fingerprint` | string | (unset) | Optional pin, in the same `SHA256:<base64>` form as a route's `agent_fingerprint`. When set, the agent refuses an edge whose server-certificate fingerprint differs. |
| `edge.proxy` | string | (unset) | An HTTP proxy to reach the edge through, with `CONNECT`: `http://[user:password@]host[:port]` or `https://...` (ports default to 80 and 443). See [Agents behind restrictive networks](#agents-behind-restrictive-networks). |
| `routes` | list | at least one | Host to local backend; see [Host routing](#host-routing-and-matching). May be split into `agent.d/`. |
| `routes[].host` | string | required | Same pattern grammar as the edge: exact, `*.suffix`, or `*`. |
| `routes[].service` | string | required | Local backend address (`host:port`) the agent dials for this host. |
| `reconnect.min_backoff` | duration | `1s` | First reconnect delay, and how long a session must last for the backoff to reset to it. |
| `reconnect.max_backoff` | duration | `30s` | Cap for the doubling backoff. Each wait is randomized to 0.5 to 1.5 times the current value, so one wait can reach 1.5 × `max_backoff`. |
| `drain_timeout` | duration | `15s` | On shutdown, finish in-flight streams for up to this long. `0` or unset uses the default (15s). |
| `log.level` | string | `info` | `trace`, `debug`, `info`, `warn`, or `error`. |
| `log.format` | string | autodetect | `text`, `json`, or `journal`. Unset autodetects: `journal` under systemd (journald), otherwise `text`. See [Log formats](#log-formats). |
| `admin.socket` | path | (unset) | Unix socket for `coen status` and `coen doctor`'s live-tunnel check. When unset, the admin socket is disabled. A small `<socket>.lock` file next to it coordinates a restart that overlaps a draining instance and is left in place. |
| `metrics.listen` | string | (unset) | `host:port` for the Prometheus endpoint (`GET /metrics`). When unset, metrics are disabled. It has no authentication, so bind it to loopback or a private interface. Rejected if it overlaps the `service` of any route on this agent. See [Prometheus metrics](#prometheus-metrics). |

Host patterns appear on both ends: the edge authorizes which agent owns a host, and the agent
maps the same host to a backend.

### Host routing and matching

The edge reads the HTTP `Host` header of each ingress connection (the TCP ingress sees
cleartext HTTP/1.x in both modes; over HTTP/3 the request's `:authority` is used), lowercases it, and strips any port before matching it against the route table.
Precedence is:

1. **Exact** host (`app.example.com`).
2. **Wildcard** `*.suffix` (`*.example.com` matches `a.example.com` and `a.b.example.com`); the
   most specific match, that is the longest suffix, wins.
3. **Default** `*`, if present, matches anything else.

The matched edge route names the owning agent's fingerprint (or several; see
[Load balancing](#load-balancing)). The edge picks a live session of that agent, opens a
stream, and forwards the request with the `Host` in the preamble; the agent matches the same
`Host` against its own `routes` and dials the backend. Both ends must agree on the host
patterns.

The edge answers with a plain HTTP status when it cannot forward:

| Code | Meaning |
| --- | --- |
| `400` | The request head was malformed, missing a `Host`, oversized, or not sent before `read_header_timeout`. |
| `404` | No route matched the `Host`. |
| `421` | HTTP/3 only: a request for a route with `http3: false` on a connection made for another host. |
| `501` | HTTP/3 only: a `CONNECT` request that is not a WebSocket. |
| `502` | A route matched but its agent is offline, a tunnel stream could not be opened, or the agent could not reach its backend; over HTTP/3 also when the service sent a response the edge cannot relay. |
| `503` | A per-route connection cap was reached (over HTTP/3, after waiting for a slot), or, over TCP, the global cap. |
| `504` | HTTP/3 only: no response within `ingress.idle_timeout` (when it is set). |

When the agent itself cannot reach a backend (the local service is down, or the agent has no
route for the host), it writes a `502` back through the tunnel, so the client gets a proper
error rather than a dropped connection. The failure is logged on the agent with the request's
`conn_id`.

### Load balancing

A route can be served by several agents. The edge keeps every live agent session, picks one
for each new connection to the service, and spreads the load:

```yaml
routes:
  # Two agents, each with its own certificate.
  - host: api.example.com
    agent_fingerprints: ["SHA256:aaa...", "SHA256:bbb..."]
    balance: least_conn          # default; or round_robin
  # Up to 256 agents that all run with one certificate.
  - host: app.example.com
    agent_fingerprint: "SHA256:ccc..."
    allow_shared_cert: true
```

- **Two ways to add agents.** Give each agent its own certificate and list the fingerprints
  (`agent_fingerprints`), or run several agents with the same certificate and set
  `allow_shared_cert`. Separate certificates can be removed one at a time (by taking a
  fingerprint off the routes) and make each agent visible in metrics. A shared certificate is simpler to roll out; one certificate can hold at
  most 256 open sessions (draining ones included) plus 256 still connecting, which bounds
  what a leaked one can take from the edge. Without
  `allow_shared_cert`, a second live connection with an already-connected fingerprint is
  refused, which stops a cloned certificate from taking over a host. A connection whose agent
  is stopping does not count, so its replacement can connect while it drains.
- **Algorithms.** `least_conn` (the default) sends a new connection to the session with the
  fewest open streams, so long-lived WebSockets do not pile up on one agent. `round_robin`
  takes the sessions in turn. Neither checks the service behind an agent: an agent whose
  service is down answers each connection with a quick `502`, so under `least_conn` it has
  few open streams and gets more of the new ones. Watch the per-route failure metrics.
- **Per connection to the service, not per request.** Over TCP the edge picks an agent when a
  client connection arrives, and further requests on that keep-alive connection stay on that
  agent. Over HTTP/3 it picks one each time it opens a new connection to the service, so the
  requests of one HTTP/3 connection can reach different agents (a kept connection stays with
  its agent). A service that keeps per-connection or in-memory session state behind several
  agents needs shared state, or `http3: false` on the route.
- **Graceful handoff.** An agent that is stopping (`SIGTERM`, `systemctl stop`) first asks the
  edge to take it out of the pool and waits for the acknowledgement, serves whatever was
  already on its way, and only then drains. New connections go to the other agents, so a
  restart costs no requests. Waiting for the acknowledgement takes at most 3 seconds, and
  never more than half of `drain_timeout`. With a `drain_timeout` under 2 seconds there is no handoff: the stopping
  agent refuses new connections, the edge sends them to another agent, and in-flight
  requests keep the whole `drain_timeout`. This needs the edge and the agent both
  at v0.4.0 or later (they negotiate it in the TLS handshake); with an older edge or
  agent, a stopping agent refuses new connections while it drains, as before, and the edge
  cannot tell those refusals apart from served connections, so it does not retry them.
- **Failover.** If the chosen session turns out to be dead (a crashed agent, whose connection
  closes or resets), the edge evicts it and tries the next one before answering, so only
  requests already in flight on that agent are lost. An agent also confirms each new stream
  with one byte, and the edge sends the request only after that, which costs one
  edge-to-agent round trip per new stream: once per client connection over TCP, and over
  HTTP/3 only when no kept connection to the service is free. If an agent refuses the stream (it is
  stopping, or its queue of streams not yet taken is full) or does not confirm it within 15 seconds (for example after its
  network went silent), it never got the request, so the edge sends it to another agent. A
  request waits at most 30 seconds in all; when no other agent is left to try, the last one
  may use all of it, unless it has just been found unresponsive. When no agent is live, the client gets a `502`.
- **Rolling restarts.** Restart agents one at a time; the others carry the traffic meanwhile.
- **Certificate rotation.** List the new fingerprint next to the old one in
  `agent_fingerprints`, then switch agents to the new certificate one at a time, and finally
  drop the old fingerprint. The edge reads routes only at startup, so each of the two config
  changes needs an edge restart, which briefly reconnects every agent.
- **Probes never get traffic.** An agent session only joins the pool after it answers a
  tunnel ping, so a `coen doctor` handshake probe, which closes right after TLS, is never
  picked.

### Listener hardening (edge)

- `ingress.max_connections` and `routes[].max_connections` cap concurrent connections globally
  and per route; over a cap the edge returns `503` without touching an agent. Over HTTP/3 the
  global cap closes the QUIC connection instead, and a request over a route cap waits up to
  `read_header_timeout` for a slot (see [HTTP/3 for clients](#http3-for-clients)).
- `ingress.read_header_timeout` (default `10s`, always enforced) bounds how long a client
  may take to send its request head.
- `ingress.idle_timeout` (default off) closes a streaming connection after that long with no
  bytes in either direction. It is off by default because it would drop an idle but healthy
  WebSocket; set it comfortably above your keepalive interval, or leave it `0`. With HTTP/3
  enabled the same value also bounds idle HTTP/3 connections, the connections to services kept
  for them, and the wait for a response (`504`); unset, the first two use `30s`.
- **Lazy backend dial** is inherent, not a knob: the edge opens a tunnel stream (and so the
  agent dials the backend) only after a complete, valid request head has arrived. Connections
  that connect and idle, or send garbage, never reach an agent or backend.

### Graceful draining

On `SIGINT` or `SIGTERM`, the edge stops accepting new ingress connections and the agent stops
accepting new streams; both then wait up to `drain_timeout` for in-flight streams to finish
before force-closing and exiting. The admin socket and the metrics endpoint stay up until the
drain is over, so `coen status` and Prometheus can follow it. An unset or `0` `drain_timeout` uses the default (15s).
A stopping agent first hands off from the edge's pools (see [Load balancing](#load-balancing)).
On the edge, new HTTP/3 connections are refused at once during the drain, and connections to
services kept for HTTP/3 clients are closed rather than reused. Under systemd, a
`drain_timeout` above 90 seconds also needs a larger `TimeoutStopSec` (for example in a
`systemctl edit coen-edge` drop-in), or systemd kills the process at its 90-second default.

See [`examples/`](examples/) for an example configuration of each variant.

## Security model

The tunnel uses TLS 1.3 with mutual certificate authentication (`RequireAndVerifyClientCert`)
and an Ed25519 CA. The edge accepts only agents whose client certificate chains to the trusted
CA, and the agent trusts only an edge whose server certificate does the same. No config file
holds a shared symmetric secret. To add an agent, issue a certificate and list its
fingerprint on an edge route; to remove one, take its fingerprint off the edge's routes and
restart the edge. CA-level revocation is not supported yet (see [Roadmap](#roadmap)).

For defence in depth beyond CA trust, the agent can pin the edge's fingerprint
(`edge_fingerprint`), and host ownership at the edge is authoritative: each
`routes` entry names the agent fingerprint(s) that own a hostname, and the set of
those fingerprints is the connection allowlist. An agent whose fingerprint owns
no route is refused, and an agent cannot serve a hostname it was not granted.

A fingerprint has at most one live session. A second connection presenting the
same certificate, for example a duplicate certificate deployed on two hosts, is
refused without disturbing the serving agent; a genuine reconnect still works,
because the previous session is already
gone by the time the agent redials. The exception is a fingerprint whose routes set
`allow_shared_cert: true`: it may hold up to 256 sessions, one per agent running the
certificate, so any copy of its key can join the pool unnoticed. Prefer one certificate
per agent, and share one only where you deploy the key yourself (for example autoscaled
replicas).

Because the edge routes on the HTTP `Host` header, it parses the request head of
each ingress request: HTTP/1.x over TCP in both modes, or, in standalone mode,
HTTP/3, which the edge terminates and re-encodes as HTTP/1.1 towards the agent. This
means the edge serves HTTP and WebSocket traffic, not arbitrary raw TCP. HTTP/2 is
not offered (the TCP listener does not advertise `h2`, so TCP clients use HTTP/1.1).
HTTP/3 has 0-RTT off, so a captured request cannot be replayed, allows at most 100
concurrent requests per QUIC connection, and is subject to the same global and
per-route caps as TCP.

The Prometheus `/metrics` endpoint has no authentication: bind it to loopback or a
private address (for example `127.0.0.1:9464`) and firewall it.

The systemd units ship with least privilege in mind. They run as a non-root `coen` user with
`NoNewPrivileges`, `ProtectSystem=strict`, and a scoped `ReadWritePaths`. A standalone edge
that binds `:443` gets exactly `CAP_NET_BIND_SERVICE`, not full root.

The public listener has several protections you configure under `ingress` (see the
[configuration reference](#listener-hardening-edge)): a TLS-handshake deadline on the tunnel
port, a request-header read deadline, an optional idle deadline, global and per-route
connection caps, and lazy backend dial so a connection reaches an agent only after sending a
complete request head. On shutdown, in-flight streams are drained up to `drain_timeout`. In a
proxied deployment nginx also fronts the ingress and adds its own slow-client protection.
Treat internet-exposed use as beta, and where you can, firewall the tunnel port to known
sources. With `tunnel.share_ingress` the tunnel answers on the public port too, so a scanner
that offers the tunnel's protocol there learns it is a Coen edge (it is asked for a client
certificate it does not have); it gains nothing more than on the tunnel port, and such
attempts count as rejected tunnel handshakes.

## Observability and diagnostics

A two-sided tunnel is awkward to debug, so observability is built into the core rather than
bolted on.

Logging uses `log/slog` in text, JSON, or a journald-friendly `journal` format (see [Log formats](#log-formats)). Each step is a named event, for example `edge.dial`,
`agent.tls_handshake`, `tunnel.established`, `agent.connected`, `ingress.accept`,
`stream.open`, `stream.closed`, and `reconnect.scheduled`, with timing and the concrete reason
on failure. The edge stamps its build version into each stream preamble, and the agent logs a
one-time `version.mismatch` warning if the edge is running a different version, so an
accidental one-sided upgrade is visible in the logs.

Because every request carries a `conn_id` in its stream preamble, the same id shows up in both
the edge and agent logs. Running `grep <conn_id>` on either host reconstructs one request's
whole lifecycle. Over HTTP/3 each request has its own `conn_id` on the edge; a request carried
on a reused connection to the service shows up in the agent's logs under the `conn_id` of the
request that opened that connection, and the edge logs `stream.reuse` for it. HTTP/3 log lines
carry `protocol=http3`; their events include `stream.reuse`, `stream.kept`, `stream.stale` (a
kept connection found closed, the request sent again), `stream.response_timeout`,
`ingress.http3_misdirected` (the `421`s) and `ingress.http3_handshake_refused`, most of them at
`debug`.

`coen status` returns a live snapshot over a local Unix socket and shows role-appropriate
fields. With a daemon running it auto-detects the role and socket from the host's process
table, so `coen status` needs no flags; `--socket`, `--config` or `--role` override it. On
the edge it lists each agent session with its source IP, connect time, fingerprint, and
whether it is draining, plus active and peak (`max`) concurrent streams, bytes in and out,
and handshake counts. When a certificate has several sessions (`allow_shared_cert`, or a
restart overlapping a drain) the summary counts sessions, certificates and draining sessions
separately, for example `agents: 3 sessions (1 draining), 2 certificates`. Handshakes are split
into `ok` (authenticated and registered), `fail` (a peer that authenticated but was not
authorized for any route, or an agent that did not answer the readiness ping), and `rejected`
(a peer refused at the TLS handshake because it presented no client certificate or an
incompatible TLS version or cipher); `duplicate` and `capped` (see
[Prometheus metrics](#prometheus-metrics)) are added to the line once either is non-zero. On a
public mTLS port `rejected` is routine scanner and probe noise that the edge correctly turns
away, so it is kept separate from `fail`. On the agent `coen status` shows whether the tunnel
is up and since when, the peer (edge) fingerprint, reconnect count, streams, bytes, handshake
counts, and the last error, if any. Add `--json` for scripts; the JSON also carries
`handshake_duplicate`, `handshake_capped`, `agents[].draining` and, on an edge serving HTTP/3,
`http3_listen`. If `admin.socket` is unset, the status socket is disabled.

Because mTLS uses two certificates, the two ends naturally show different fingerprints: each
side reports the peer's certificate. To let you cross-check that the right two daemons are
connected, each also prints its own certificate fingerprint as `self_fp`. The agent's
`peer_fp` should equal the edge's `self_fp`, and the fingerprint the edge lists for an agent
should equal that agent's `self_fp`.

`coen doctor` runs role-aware checks and exits non-zero if any fails, so it fits into deploy
scripts. On the edge: the PKI files are present and parse, the edge keypair loads, the public
certificate loads (standalone), each route's fingerprints are well formed, and the tunnel and
ingress ports can be bound (with `tunnel.share_ingress` it reports that agents may also use the
ingress port, and checks the tunnel port only when `tunnel.listen` is set). With `ingress.http3.enabled` it also checks that the UDP port can
be bound and, on Linux, whether `net.core.rmem_max` and `net.core.wmem_max` reach the 7340032
bytes QUIC asks for (advisory: a smaller value still passes). With `metrics.listen` set it
checks that the metrics port can be bound. On the agent: the PKI files and keypair, the
`edge_fingerprint` format, the metrics bind, DNS for the edge (for the proxy instead, with
`edge.proxy`), TCP reachability (through the proxy, with `CONNECT`), an mTLS handshake with
the pin, the edge certificate's validity window against the local clock, and
that each route's service accepts a connection. A port held by the role's own running daemon
counts as a pass. `--json` prints the results as JSON. With a daemon running it auto-detects the role, and
when the agent's tunnel is already up it verifies edge reachability and mTLS from that live
tunnel rather than opening a fresh connection, so a health check never perturbs the serving
edge. Only the `log.level` can be
changed on a running daemon (with `systemctl reload` or `SIGHUP`); other changes need a
restart.

### Prometheus metrics

Set `metrics.listen` on the edge, the agent, or both, and the daemon serves the Prometheus
text format on `GET /metrics`. The endpoint is off by default and has no authentication,
so bind it to loopback or a private interface. The config is rejected if the address
overlaps `tunnel.listen` or `ingress.listen`: the same port, and the same address or a
wildcard (`0.0.0.0`, `::`, or an empty host, all dual-stack in Go). `localhost` counts as
the loopback addresses; other hostnames are compared as written, because loading a config
never does a DNS lookup. On the agent it must also not overlap any route's
`service` address, since a metrics endpoint on a backend's port would expose it publicly. An address the host does not have, or a
port it may not bind, stops the daemon at startup. A port held by another process, including
a second live coen daemon or the other role, stops it too. The one exception is a previous
instance of the same role that is draining (it reports `coen_draining 1`): the daemon
starts, logs `metrics.listen_busy`, and claims the port once it is free; the predecessor's
own `drain_timeout` bounds the wait. If the port ends up held by anything else, it logs
`metrics.listen_failed` and runs without metrics until restarted. `coen doctor` checks that the
address can be bound. The endpoint stays up during a graceful
shutdown until the drain finishes, so you can watch in-flight streams fall to zero. See
[`examples/08-prometheus-metrics`](examples/08-prometheus-metrics/) for a scrape config and
alert queries.

The `route` label is always a host pattern from the config, never a value taken from a
request, so the number of series is fixed by configuration and does not grow with traffic.
Failures that happen before a route is known carry no `route` label. Every known `reason`
starts at `0`, so `rate()` works from the first scrape.

| Metric | Type | Role | Labels | Meaning |
| --- | --- | --- | --- | --- |
| `coen_build_info` | gauge | both | `role`, `version` | Always `1`; carries the build version. |
| `coen_process_start_time_seconds` | gauge | both | | Daemon start time, Unix seconds. |
| `coen_streams_active` | gauge | both | `route` | Streams open right now, including connections to the service the edge keeps open between HTTP/3 requests. |
| `coen_streams_total` | counter | both | `route` | Streams opened: one per TCP connection, and over HTTP/3 one per connection to the service, which carries one or more of an HTTP/3 connection's requests in turn. |
| `coen_streams_http3_total` | counter | edge | `route` | Of those, the streams opened for HTTP/3 requests (WebSockets over HTTP/3 included); each carries one or more requests in turn. |
| `coen_http3_requests_total` | counter | edge | `route` | HTTP/3 requests sent to the service, over the streams in `coen_streams_http3_total`; requests minus streams is the number served on a reused connection. A request sent again after a kept connection turned out closed counts once. |
| `coen_stream_bytes_total` | counter | both | `route`, `direction` | Bytes carried by streams, counted as they flow, so long-lived WebSockets show steady throughput. `in` is client to backend, `out` is backend to client. Over HTTP/3, the bytes of the HTTP/1.1 form exchanged with the service. |
| `coen_streams_peak` | gauge | both | | Highest concurrent stream count since start. |
| `coen_draining` | gauge | both | | `1` once shutdown has started and in-flight streams are draining, else `0`. |
| `coen_tunnel_handshakes_total` | counter | both | `result` | Tunnel connections, as `coen status` counts them. Edge: `ok`, `fail` (authenticated but not allowed), `duplicate` (a second connection with a certificate that already has a live session and is not shared, for example a cloned certificate, or a `coen doctor` probe that cannot use the running agent's live tunnel: one from another host, or without a reachable `admin.socket`), `capped` (refused at a certificate's limit of 256 open sessions, draining ones included, or 256 still connecting), `rejected` (refused at TLS); a real agent that fails the readiness ping counts as `fail`. Agent: `ok`, `fail` (the dial, the TLS handshake, or the edge pin failed). |
| `coen_agent_connected` | gauge | edge | `fingerprint` | `1` when that agent is connected (also while it drains), `0` when a configured agent is offline. To alert on a route losing capacity, use `coen_agent_sessions == 0`. |
| `coen_agent_sessions` | gauge | edge | `fingerprint` | Sessions taking new traffic for that fingerprint (draining ones excluded); above `1` only with `allow_shared_cert`. |
| `coen_agent_streams_active` | gauge | edge | `fingerprint` | Streams open or being set up right now on that agent's sessions, including draining ones and connections kept open between HTTP/3 requests: the load `least_conn` balances on. A stalled agent shows its stream attempts here until they time out. |
| `coen_agent_streams_total` | counter | edge | `fingerprint` | Streams opened on that agent since start, which shows how load is balanced. Like `coen_streams_total`, it counts connections to the service, not the HTTP/3 requests carried on a reused one. |
| `coen_ingress_rejected_total` | counter | edge | `reason`, `route` | Requests the edge answered itself. Without a route: `max_connections` (503 over TCP; over HTTP/3 the QUIC connection is closed instead; the cap is checked before anything is read, so this counts every connection turned away, probes included), `bad_request` (400), `no_route` (404). With a route: `route_max_connections` (503; over HTTP/3 after waiting up to `read_header_timeout` for a slot), `no_agent` (502), `stream_error` (502), `response_timeout` (504: an HTTP/3 request with no response within `ingress.idle_timeout`), `bad_response` (502: an HTTP/3 request whose service sent a response the edge cannot relay, such as a malformed head or a WebSocket upgrade it ignored), `http3_off` (421: an HTTP/3 request for a route with `http3: false`, on a connection made for another host). A connection that sends no request at all, such as a TCP health check or a browser preconnect, is not a rejected request and is not counted here. A TLS handshake that fails, or is abandoned after the ClientHello, is a `bad_request`. |
| `coen_ingress_header_timeouts_total` | counter | edge | | TCP ingress connections closed at `read_header_timeout` without sending any request byte, such as idle browser preconnects (idle HTTP/3 connections are not counted). A sudden rise suggests an idle-connection flood. |
| `coen_tunnel_up` | gauge | agent | | `1` while the tunnel to the edge is established. |
| `coen_tunnel_reconnects_total` | counter | agent | | Reconnect attempts. |
| `coen_stream_errors_total` | counter | agent | `reason`, `route` | Streams the agent could not serve. Without a route: `preamble_error` (a malformed or late stream header; the stream is closed) and `no_route` (502). A stream cut off by an edge restart is not counted. With a route: `dial_error` (502, backend unreachable). |

## Running as a systemd service

`coen install` writes a hardened unit and an example config for each role.

```bash
sudo coen install edge     # writes /etc/systemd/system/coen-edge.service and /etc/coen/edge.yaml
sudo coen install agent    # writes /etc/systemd/system/coen-agent.service and /etc/coen/agent.yaml

# Edit the configs, put your PKI under /etc/coen/pki, then enable the service.
sudo systemctl enable --now coen-edge      # on the public host
sudo systemctl enable --now coen-agent     # on the private host
```

The unit runs `/usr/local/bin/coen` unless you pass `--bin "$(command -v coen)"` (a
`go install` puts it in `~/go/bin`); `--unit-dir` (default `/etc/systemd/system`) and
`--config-dir` (default `/etc/coen`) move the files, and `--force` replaces an existing unit.
An existing config is never overwritten, and the `edge.d/` or `agent.d/` drop-in directory is
created next to it.

If you installed a `.deb`, `.rpm` or `.apk` package, skip `coen install`: the package already
ships both units (in `/usr/lib/systemd/system`, running `/usr/bin/coen`) and example configs.
A unit written to `/etc/systemd/system` would override the package's, and with the default
`--bin` it would point at a binary that does not exist. A package upgrade replaces the binary
but does not restart a running service; run `sudo systemctl restart coen-<role>` afterwards.

The systemd unit runs as a dedicated non-root `coen` user. `coen install` does
not create it (that would mutate system accounts); if it is missing, install
prints the exact `groupadd`/`useradd` commands to create it. The `.deb`, `.rpm`,
and `.apk` packages create the user for you. With a `drain_timeout` above 90 seconds, raise
the unit's `TimeoutStopSec` in a drop-in (`sudo systemctl edit coen-edge`).

On macOS, `coen install` writes a launchd `LaunchDaemon` to
`/Library/LaunchDaemons/com.coen.<role>.plist` (load it with
`sudo launchctl bootstrap system /Library/LaunchDaemons/com.coen.<role>.plist`).
On systems other than Linux and macOS, `coen install` is unavailable and prints
how to run `coen <role>` under that platform's own service manager.

## Roadmap

Delivered:

- [x] Multi-route and multiple hostnames (host-based routing at the edge, across multiple agents)
- [x] Public-listener hardening: ingress idle-deadlines, connection caps, lazy backend dial
- [x] Bounded graceful draining of in-flight streams on shutdown
- [x] Prometheus `/metrics` endpoint, per route and per agent
- [x] Load balancing across several agents per host, with failover
- [x] HTTP/3 (QUIC) for clients in standalone mode
- [x] Agents on port 443: the tunnel on the standalone ingress port, and through HTTP proxies

Still planned (the architecture leaves room for them):

- [ ] ACME and Let's Encrypt automatic certificates for standalone mode
- [ ] A WebSocket transport for the tunnel, through TLS-intercepting proxies and CDNs
- [ ] Certificate rotation and revocation without an edge restart

## Contributing

Contributions are welcome, whether it is a bug fix, a roadmap item, docs, or tests.

1. For anything non-trivial, open an issue first so we can agree on the approach before you
   spend time on it.
2. Fork and branch from `main`, for example `feat/multi-route` or `fix/handshake-deadline`.
3. The codebase is test-first, so add or update tests alongside your change.
4. Keep it green and tidy before opening a pull request:

   ```bash
   golangci-lint run ./...   # errcheck, staticcheck, govet, ineffassign, unused, gofmt
   go test -race ./...       # the whole suite passes under the race detector
   govulncheck ./...         # scan for known vulnerabilities
   ```

   CI runs the same checks (lint, a Go 1.26 and 1.27 test matrix under `-race`,
   and `govulncheck`) on every push and pull request, plus a coverage job
   (`go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...`); keep total
   coverage at 85% or higher.

5. Open a pull request that explains what changed and why. Keep it focused, and reference the
   issue it addresses. Conventional-commit-style messages (`feat:`, `fix:`, `docs:`) are
   appreciated.

If you are new to the code, the [project layout](#project-layout) is the fastest way in. Good
first changes include roadmap items, extra `coen doctor` checks, and wider test coverage.

## Reporting bugs and security issues

For bugs and feature requests, [open an issue](https://github.com/baspeters/coen/issues). A
minimal reproduction, your `coen version`, the relevant `coen doctor` output, and the log lines
around the failing `conn_id` make a fix much faster.

For security vulnerabilities, please do not open a public issue. Report it privately through
GitHub Security Advisories (Security, then "Report a vulnerability") so a fix can ship before
disclosure.

## Project layout

```
cmd/coen/            thin main() entrypoint
internal/
  cli/               cobra commands (edge, agent, cert, doctor, status, install, version)
  edge/              public server: TCP and HTTP/3 ingress, Alt-Svc, tunnel server,
                     session registry and balancer, host router, connection caps,
                     HTTP/3 stream reuse, graceful draining and handoff
  agent/             private client: dial and reconnect, per-host stream-to-backend bridge
  route/             host-pattern matcher (exact > wildcard > default), shared by edge/agent
  tunnel/            shared mTLS config and ALPN versioning, yamux sessions, stream
                     preamble and accept byte, drain control stream
  proxy/             byte-copy plumbing, idle-deadline and prefix conn wrappers
  pki/               Ed25519 CA, certificate issuance, fingerprints
  config/            YAML load, .d drop-in merge, and validation
  obs/               slog logging, correlation IDs, live and per-route counters
  metrics/           opt-in Prometheus /metrics endpoint (hand-written text format)
  netx/              platform-neutral network error checks (address in use, not available)
  admin/             local unix-socket status and control server
  doctor/            preflight diagnostic checks
  errpage/           minimal HTML error pages written by edge and agent
  e2e/               end-to-end tests (HTTP, WebSocket, correlation, host routing, load
                     balancing, HTTP/3, metrics)
examples/            example configs for each setup variant and config option
packaging/nginx/     example proxied-mode vhost snippet
packaging/systemd/   units shipped in the .deb, .rpm and .apk packages
packaging/scripts/   package install and remove hooks
```

## FAQ

Do I need to open inbound ports on the private machine? No. The agent only makes an outbound
connection to the edge.

Does it support WebSockets? Yes. The edge reads a request's `Host` header to route it, then
pipes the connection through unchanged, so `Upgrade` handshakes and long-lived sockets work.
A browser may also open one over HTTP/3; the edge turns it into an ordinary HTTP/1.1 upgrade
towards the service.

Can several agents connect to one edge? Yes. One edge fronts many agents, matched by
client-certificate fingerprint. A hostname can be owned by one agent, or shared by several for
load balancing and failover (`agent_fingerprints`, `balance`; see
[Load balancing](#load-balancing)).

Can one agent serve several hostnames? Yes. Give the agent a route per host, each mapping to a
local backend, and grant it those hosts on the edge.

Does it tunnel arbitrary TCP? No. The edge routes on the HTTP `Host` header, so it serves
HTTP/1.x, HTTP/3 (standalone mode) and WebSocket traffic. Raw non-HTTP TCP and HTTP/2 at the
edge are out of scope.

Does my service need HTTP/3 support? No. The edge terminates HTTP/3 and the service always
sees HTTP/1.1. A service that ties authentication to its TCP connection (Windows sign-in with
NTLM or Negotiate) should be kept off HTTP/3 with `http3: false`; see
[HTTP/3 for clients](#http3-for-clients).

Where do the public TLS certificates come from? You provide them in standalone mode (for
example, Let's Encrypt), or nginx owns them in proxied mode. The Coen CA is only for the
internal tunnel, never for public traffic.

## The name

Coen is a nod to the Coentunnel, a road tunnel under the North Sea Canal in Amsterdam. It also
happens that `COEN` spells `2636` on a phone keypad, which is Coen's tunnel port. Gophers dig
tunnels; so does Coen.

## Acknowledgements

The Go gopher was created by [Renée French](https://reneefrench.blogspot.com/); the banner is
drawn in that style. Coen builds on [hashicorp/yamux](https://github.com/hashicorp/yamux) for
stream multiplexing, [quic-go](https://github.com/quic-go/quic-go) for HTTP/3, and
[spf13/cobra](https://github.com/spf13/cobra) for the CLI.

## License

Coen is released under the [MIT License](LICENSE).
