# 03. Multiple routes, one agent

One agent fronting several hostnames, each mapped to a different local backend.
The edge owns both hosts under the same agent fingerprint; the agent decides
which backend each host reaches.

```
client --> edge :443 --+-- app.example.com --mTLS--> agent --> 127.0.0.1:8080
                       +-- api.example.com --mTLS--> agent --> 127.0.0.1:9090
```

## Notes

- In standalone mode the edge serves one TLS certificate for all hosts, so use a
  multi-SAN (or wildcard) certificate covering `app.example.com` and
  `api.example.com`. Per-host certificates fit the proxied/nginx examples (see
  07), and ACME automation is on the roadmap.
- Both edge routes carry the same `agent_fingerprint`, so the derived allowlist
  has a single agent.
- The agent's `routes` use the same host patterns, mapping each to its backend.

## Verify

```
curl https://app.example.com/    # served by 127.0.0.1:8080
curl https://api.example.com/     # served by 127.0.0.1:9090
```
