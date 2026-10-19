# 10. HTTP/3 for clients

The standalone edge from example 01, also serving HTTP/3 (QUIC over UDP). The
edge terminates HTTP/3 and sends each request through the tunnel as HTTP/1.1,
so the agent needs nothing new. A second host, `intranet.example.com`, stays on
TCP (see [Keeping a host off HTTP/3](#keeping-a-host-off-http3)). Connections to
the service are reused across a client's HTTP/3 requests, as they are over TCP.

```
client --HTTP/3 (UDP 443)---\
                             edge (terminates TLS and QUIC) --mTLS--> agent --> 127.0.0.1:8080
client --HTTPS (TCP 443)----/
```

## Prerequisites

- Everything from example 01, with a certificate covering both
  `app.example.com` and `intranet.example.com`.
- UDP 443 open in the firewall, next to TCP 443.
- On Linux, for full speed, socket buffers as large as QUIC asks for:

  ```sh
  sudo sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032
  ```

  (persist it in `/etc/sysctl.d/`). On Linux, `coen doctor --role edge` reports
  whether they are large enough.

## How clients switch to HTTP/3

A browser's first request goes over TCP. The edge adds
`Alt-Svc: h3=":443"; ma=86400` to the first response on each TCP connection, and
the browser uses HTTP/3 from then on. If the service sets its own `Alt-Svc`, the
edge leaves it alone. To let browsers use HTTP/3 from the very first request,
publish a DNS `HTTPS` record:

```
app.example.com. 300 IN HTTPS 1 . alpn="h3"
```

## Keeping a host off HTTP/3

Some services tie a login to the TCP connection: Windows sign-in (NTLM, or
Negotiate/Kerberos) authenticates the connection, not each request. HTTP/3 (like
HTTP/2) sends many requests over one connection, so it cannot carry that. Over
TCP the edge passes each client connection through as one connection to the
service, so it works there. `http3: false` on a route keeps its host on TCP:

- the first TCP response on each connection gets `Alt-Svc: clear`, in place of any
  `Alt-Svc` the service sets, so a browser forgets an HTTP/3 alternative it learned
  before (later responses pass unchanged, so the service should not advertise
  HTTP/3 itself);
- an HTTP/3 handshake for the host is refused, so a browser that found HTTP/3
  another way (a DNS `HTTPS` record) falls back to TCP;
- a request for the host on an HTTP/3 connection made for another host (browsers
  reuse one for every host its certificate covers) gets `421 Misdirected
  Request`, which tells the browser to retry on a new connection, whose handshake
  is then refused.

The 421s count as `coen_ingress_rejected_total{reason="http3_off"}`. Leave such hosts
out of DNS `HTTPS` records with `alpn="h3"`.

## Verify

```sh
# HTTP/3 directly (curl built with HTTP/3 support)
curl --http3-only -sI https://app.example.com/

# Over TCP: the first response advertises HTTP/3
curl -sI https://app.example.com/ | grep -i alt-svc

# The host kept off HTTP/3: Alt-Svc: clear over TCP, and HTTP/3 is refused
curl -sI https://intranet.example.com/ | grep -i alt-svc
curl --http3-only -sI https://intranet.example.com/   # fails in the TLS handshake
```

The edge's metrics count both: `coen_streams_total` has one stream per TCP
connection, and over HTTP/3 one per connection to the service, and
`coen_streams_http3_total` counts the HTTP/3 ones. `coen_http3_requests_total`
counts the HTTP/3 requests those streams carried.

## Notes

- WebSockets work over both: one opened over HTTP/3 reaches the service as an
  ordinary HTTP/1.1 upgrade.
- HTTP/3 requests reuse connections to the service, as TCP clients do: a
  connection carries one HTTP/3 connection's requests in turn, never another's.
  Only requests that may be sent twice (`GET`, `PUT`, `DELETE` and the like, or
  one with an `Idempotency-Key`) take a kept one; a `POST` opens a fresh one, so
  it is never sent twice.
- With `idle_timeout` set (60s here), a request with no response in that time
  gets a `504`.
- 0-RTT is off, so a captured request cannot be replayed by anyone else.
- Behind nginx (proxied mode), let nginx serve HTTP/3 instead; see the
  [HTTP/3 section](../../README.md#http3-for-clients) of the main README.
