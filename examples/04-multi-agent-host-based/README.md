# 04. Multiple agents, host-based ownership (with `.d` drop-ins)

Two agents on two different private hosts, each owning a distinct hostname. This
is the core multi-agent model: the edge keeps a session registry keyed by
client-cert fingerprint and routes each host to its owning agent. For several agents serving the same host
(load balancing), see [09-load-balancing](../09-load-balancing/).

```
                        +-- app.example.com --mTLS--> agent A (host 1) --> 127.0.0.1:8080
client --> edge :8000 --+
                        +-- api.example.com --mTLS--> agent B (host 2) --> 127.0.0.1:9090
```

## `.d` drop-ins

`edge.yaml` has no inline routes. Each owner's route lives in its own file under
`edge.d/`:

```
edge.yaml
edge.d/
  team-a.yaml   # app.example.com -> agent A's fingerprint
  team-b.yaml   # api.example.com -> agent B's fingerprint
```

coen loads `edge.yaml`, then merges every `edge.d/*.yaml` in sorted filename
order. Drop-ins are routes-only fragments; any other top-level key is rejected.
Adding a third agent is a new file, with no shared list to edit. A duplicate host
across files is a load error that names both files.

## Wire it up

1. Issue a client cert per agent, then put each agent's fingerprint into the
   matching `edge.d/*.yaml`. `coen cert agent` always writes `agent.crt` and `agent.key`, so on the CA host rename
   each pair before issuing the next, for example
   `coen cert agent --name agent-a && mv /etc/coen/pki/agent.crt /etc/coen/pki/agent-a.crt && mv /etc/coen/pki/agent.key /etc/coen/pki/agent-a.key`,
   and the same for `agent-b`.
   Copy `ca.crt` and that agent's pair to its host (never `ca.key`).
2. Deploy `agent-app.yaml` to host 1 and `agent-api.yaml` to host 2.
3. Start the edge and both agents. `coen status` on the edge lists both connected
   agents (it uses the `admin.socket` set in `edge.yaml`).
