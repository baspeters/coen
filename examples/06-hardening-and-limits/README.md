# 06. Hardening and limits

Every TCP public-listener knob, bounded graceful draining, and the agent's
reconnect backoff, on one edge and one agent. HTTP/3 adds a few of its own; see
[10-http3](../10-http3/).

## Ingress knobs

| Knob | This example | Meaning |
|------|--------------|---------|
| `ingress.max_connections` | `1024` | Global cap on concurrent ingress connections (TCP and HTTP/3 together). Over the cap a TCP connection gets a `503`. `0` means unlimited. |
| `ingress.read_header_timeout` | `10s` | Bound on reading the HTTP request head (slow-loris protection). Always on; defaults to `10s`. |
| `ingress.idle_timeout` | `120s` | Rolling idle deadline while streaming; a connection with no traffic for this long is closed. `0` disables it. |
| `routes[].max_connections` | `256` / `64` | Per-route cap, so one backend cannot consume all global slots. `0` means unlimited. |
| `drain_timeout` (edge and agent) | `30s` | On shutdown, stop accepting and finish in-flight streams for up to this long before force-closing. Unset or `0` uses the default, `15s`. |
| `agent_wait` (edge) | `5s` (default) | A request whose route has no agent (one restarting) waits this long for one before it gets `502`. `0` answers at once. |
| `reconnect.min_backoff` / `max_backoff` (agent) | `1s` / `30s` | Bounds of the agent's exponential reconnect backoff (with jitter); these are the defaults. |

## Lazy backend dial

There is no knob for this; it is inherent. The edge opens the tunnel stream (and
so the agent's backend dial) only after it has read a complete, valid request
head. Connections that connect and idle, or send garbage, never reach an agent or
backend.

## Note on idle_timeout and WebSockets

`idle_timeout` closes a connection with no bytes in either direction for the
timeout. A long-lived but quiet WebSocket is dropped unless the app sends
periodic pings or pongs (any byte resets the deadline). Pick a value comfortably
larger than your keepalive interval, or leave it `0` (disabled) if you cannot
guarantee keepalives.
