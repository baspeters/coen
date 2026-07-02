# 05 — Wildcard and default routes

Demonstrates the matching precedence: **exact > wildcard (`*.suffix`) > default
(`*`)**.

| Request host | Matches | Backend |
|--------------|---------|---------|
| `app.example.com` | exact `app.example.com` | `127.0.0.1:8080` |
| `www.example.com` | wildcard `*.example.com` | `127.0.0.1:8090` |
| `deep.sub.example.com` | wildcard `*.example.com` | `127.0.0.1:8090` |
| `other.org` | default `*` | `127.0.0.1:8099` |

- A `*.example.com` wildcard matches any host ending in `.example.com` with at
  least one leading label. When several wildcards match, the **longest** suffix
  wins.
- The default `*` route is optional; without it, an unmatched host gets a `404`.
- Both the edge (ownership) and the agent (backend mapping) use the same
  patterns.

## Notes

- Standalone mode serves one certificate, so use a wildcard TLS cert for
  `*.example.com` (plus a SAN for `example.com` if you serve the apex).
