# 08. Prometheus metrics

The edge and the agent can each serve Prometheus metrics on `GET /metrics`. The
endpoint is off by default; set `metrics.listen` to turn it on.

## Exposure

The endpoint has no authentication, so bind it to loopback or a private
interface and let a local Prometheus (or an agent such as Grafana Alloy) scrape
it. `prometheus.yml` here is a minimal scrape config for both daemons on one
host. `coen doctor` checks that the metrics address can be bound.

## Wire it up

1. Set `metrics.listen` as in `edge.yaml` (`127.0.0.1:9464`) and `agent.yaml`
   (`127.0.0.1:9465`), run `coen doctor`, and restart the daemons.
2. Check each endpoint on its own host:
   `curl -s http://127.0.0.1:9464/metrics | grep coen_build_info` on the edge, and
   the same with `:9465` on the agent.
3. The edge and the agent normally run on different hosts. Run a Prometheus (or
   Alloy) on each host with only that host's job from `prometheus.yml`, or one
   Prometheus that can reach both over a private network; then set
   `metrics.listen` to that private address instead of loopback.

## What to alert on

| Signal | Query |
|--------|-------|
| An agent is offline (edge) | `coen_agent_connected == 0` |
| The tunnel is down (agent) | `coen_tunnel_up == 0` |
| Requests failing on a route (edge) | `rate(coen_ingress_rejected_total{route!="",reason!="http3_off"}[5m]) > 0` (the `http3_off` 421s are normal browser behaviour; see example 10) |
| An agent (certificate) with no session taking traffic (edge) | `coen_agent_sessions == 0` |
| Backend unreachable (agent) | `rate(coen_stream_errors_total{reason="dial_error"}[5m]) > 0` |
| Scanner noise on the tunnel port (edge) | `rate(coen_tunnel_handshakes_total{result="rejected"}[5m])` |

Every route label is a host pattern from the config, so the number of series is
fixed by configuration and does not grow with traffic. See the README's
[Prometheus metrics](../../README.md#prometheus-metrics) section for the full list.
