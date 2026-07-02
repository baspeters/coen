# 07 — Proxied, multiple hosts with distinct TLS certs

The realistic production shape for several public hostnames that need
**different certificates**: nginx does SNI + per-host TLS on `:443` and forwards
each vhost to one coen edge (proxied mode), which routes by `Host` to the owning
agent.

```
                    ┌ app.example.com (cert A) ┐          ┌ app -> agent A -> :8080
client ─HTTPS─▶ nginx ┤                          ├─HTTP─▶ edge ┤
                    └ api.example.com (cert B) ┘  (:8000)     └ api -> agent B -> :9090
```

## Why proxied for multi-cert

Standalone mode serves a single certificate for all hosts (a SAN/wildcard cert —
see examples 03 and 05). When each hostname needs its **own** certificate, let
nginx terminate TLS per `server_name` and forward to the edge. Automatic
per-host certificates (ACME) at the standalone edge are on the roadmap.

## Layout

```
edge.yaml            # proxied, no inline routes
edge.d/
  app.yaml           # app.example.com -> agent A
  api.yaml           # api.example.com -> agent B
agent-app.yaml       # agent A (host 1)
agent-api.yaml       # agent B (host 2)
nginx.conf           # two TLS vhosts -> the shared edge upstream
```

## Wire it up

1. Obtain per-host certs (e.g. `certbot -d app.example.com -d api.example.com`).
2. Put the `map` block in `http { }` and both `server { }` blocks in your sites
   config; `nginx -t && systemctl reload nginx`.
3. Fill each agent's fingerprint into the matching `edge.d/*.yaml`, deploy the two
   agent configs, and start the edge + both agents.
