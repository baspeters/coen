# 06 — Hardening and limits

Every public-listener knob, plus bounded graceful draining, on one edge.

## Ingress knobs

| Knob | This example | Meaning |
|------|--------------|---------|
| `ingress.max_connections` | `1024` | Global cap on concurrent ingress connections. Over the cap → `503`. `0` = unlimited. |
| `ingress.read_header_timeout` | `10s` | Bound on reading the HTTP request head (slow-loris protection). Always on; defaults to `10s`. |
| `ingress.idle_timeout` | `120s` | Rolling idle deadline while streaming; a connection with no traffic for this long is closed. `0` = disabled. |
| `routes[].max_connections` | `256` / `64` | Per-route cap, so one backend can't consume all global slots. `0` = unlimited. |
| `drain_timeout` (edge & agent) | `30s` | On shutdown, stop accepting and finish in-flight streams for up to this long before force-closing. `0` = immediate. |

## Lazy backend dial

There is no knob for this — it is inherent. The edge opens the tunnel stream
(and thus the agent's backend dial) only **after** it has read a complete, valid
request head. Connections that connect and idle, or send garbage, never reach an
agent or backend.

## ⚠️ idle_timeout and WebSockets

`idle_timeout` closes a connection with no bytes in **either** direction for the
timeout. A long-lived but quiet WebSocket will be dropped unless the app sends
periodic pings/pongs (any byte resets the deadline). Pick a value comfortably
larger than your keepalive interval, or leave it `0` (disabled) if you can't
guarantee keepalives.
