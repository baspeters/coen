# 09. Load balancing

One edge spreads each host over several agents, with automatic failover.

## Two ways to add agents

| Route | How | When |
|-------|-----|------|
| `api.example.com` | `agent_fingerprints` lists two agents, each with its own certificate (`agent-1.yaml`, `agent-2.yaml`) | You want to remove or watch agents one at a time |
| `app.example.com` | `allow_shared_cert: true`; every agent runs `agent-shared.yaml` with the same certificate | You want to add agents without issuing certificates |

Issue one certificate per agent on the CA host and paste each printed fingerprint into
`edge.yaml`. `coen cert agent` always writes `agent.crt` and `agent.key`, so rename each
pair before issuing the next:

```sh
coen cert agent --name agent-1 && mv /etc/coen/pki/agent.crt /etc/coen/pki/agent-1.crt && mv /etc/coen/pki/agent.key /etc/coen/pki/agent-1.key
coen cert agent --name agent-2 && mv /etc/coen/pki/agent.crt /etc/coen/pki/agent-2.crt && mv /etc/coen/pki/agent.key /etc/coen/pki/agent-2.key
coen cert agent --name shared  && mv /etc/coen/pki/agent.crt /etc/coen/pki/shared.crt  && mv /etc/coen/pki/agent.key /etc/coen/pki/shared.key
```

Copy `ca.crt` and each agent's pair to that agent's host (never `ca.key`).

## Balancing

`least_conn` (the default) sends a new client connection to the agent session with the fewest
open streams, which keeps long-lived WebSockets from piling up on one agent. `round_robin`
takes the sessions in turn. Over TCP the choice is made per client connection; further requests
on the same keep-alive connection stay on the same agent. Over HTTP/3 it is made per connection
to the service: a kept one carries later idempotent requests (`GET` and the like) of that
HTTP/3 connection to the same agent, while concurrent requests and requests such as `POST` open
new streams, which may go to other agents.

## Failover and rolling restarts

A stopping agent asks the edge to take it out of the pool before it drains, and if an
agent's tunnel dies the edge evicts that session and retries the request on another one, so
restarting agents one at a time loses no requests. A single agent can also be reloaded or
upgraded without a gap, with `systemctl reload coen-agent` (see the README's
[Seamless agent reloads and upgrades](../../README.md#seamless-agent-reloads-and-upgrades)). The handoff needs the edge and the agents
at v0.4.0 or later, and the agent's `drain_timeout` at least `2s` (the default `15s` is fine). To rotate an agent's certificate, add the new fingerprint to `agent_fingerprints`,
switch the agent to the new certificate, then drop the old fingerprint; each edge config
change takes effect on an edge restart.

## Watching it

With `metrics.listen` set, as in this `edge.yaml` (see [08-prometheus-metrics](../08-prometheus-metrics/)),
`coen_agent_streams_total{fingerprint=...}` shows how streams are spread, and
`coen_agent_streams_active` is the load `least_conn` balances on, and
`coen_agent_sessions` shows how many agents share a certificate. `coen status` on the edge
lists every session (it uses the `admin.socket` set in `edge.yaml`).

## Verify

```sh
for i in $(seq 20); do curl -s -o /dev/null https://api.example.com/; done
curl -s 127.0.0.1:9464/metrics | grep coen_agent_streams_total   # both agents got streams
coen status                                                      # on the edge: every session
```
