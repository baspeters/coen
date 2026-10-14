# 09. Load balancing

One edge spreads each host over several agents, with automatic failover.

## Two ways to add agents

| Route | How | When |
|-------|-----|------|
| `api.example.com` | `agent_fingerprints` lists two agents, each with its own certificate (`agent-1.yaml`, `agent-2.yaml`) | You want to revoke or watch agents one at a time |
| `app.example.com` | `allow_shared_cert: true`; every agent runs `agent-shared.yaml` with the same certificate | You want to add agents without issuing certificates |

Issue the certificates with `coen cert agent --name agent-1` (and so on) and paste the
printed fingerprints into `edge.yaml`.

## Balancing

`least_conn` (the default) sends a new client connection to the agent session with the fewest
open streams, which keeps long-lived WebSockets from piling up on one agent. `round_robin`
takes the sessions in turn. The choice is made per client connection; further requests on the
same keep-alive connection stay on the same agent.

## Failover and rolling restarts

A stopping agent asks the edge to take it out of the pool before it drains, and if an
agent's tunnel dies the edge evicts that session and retries the request on another one, so
restarting agents one at a time loses no requests (with edge and agents at this version or
later). To rotate an agent's certificate, add the new fingerprint to `agent_fingerprints`,
switch the agent to the new certificate, then drop the old fingerprint; each edge config
change takes effect on an edge restart.

## Watching it

With `metrics.listen` set (see [08-prometheus-metrics](../08-prometheus-metrics/)),
`coen_agent_streams_total{fingerprint=...}` shows how streams are spread, and
`coen_agent_sessions` shows how many agents share a certificate. `coen status` on the edge
lists every session.
