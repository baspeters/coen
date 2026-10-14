# 08. Prometheus metrics

The edge and the agent can each serve Prometheus metrics on `GET /metrics`. The
endpoint is off by default; set `metrics.listen` to turn it on.

## Exposure

The endpoint has no authentication, so bind it to loopback or a private
interface and let a local Prometheus (or an agent such as Grafana Alloy) scrape
it. `prometheus.yml` here is a minimal scrape config for both daemons on one
host. `coen doctor` checks that the metrics address can be bound.

## What to alert on

| Signal | Query |
|--------|-------|
| An agent is offline (edge) | `coen_agent_connected == 0` |
| The tunnel is down (agent) | `coen_tunnel_up == 0` |
| Requests failing on a route (edge) | `rate(coen_ingress_rejected_total{route!=""}[5m]) > 0` |
| Backend unreachable (agent) | `rate(coen_stream_errors_total{reason="dial_error"}[5m]) > 0` |
| Scanner noise on the tunnel port (edge) | `rate(coen_tunnel_handshakes_total{result="rejected"}[5m])` |

Every route label is a host pattern from the config, so the number of series is
fixed by configuration and does not grow with traffic. See the README's
[Prometheus metrics](../../README.md#prometheus-metrics) section for the full list.
