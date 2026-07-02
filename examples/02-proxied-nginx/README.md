# 02 — Proxied behind nginx

Run coen behind an existing nginx vhost. nginx owns `:443` and the public
certificate; the coen edge runs in **proxied** mode on loopback and receives
plain HTTP. coen still routes by the `Host` header, so nginx only needs to
forward.

```
client ─HTTPS▶ nginx (:443, TLS) ─HTTP▶ edge (127.0.0.1:8000) ─mTLS─▶ agent ─▶ 127.0.0.1:8080
```

## Wire it up

1. Put the `map` block from `nginx.conf` in your `http { }` context and the
   `server { }` block in your sites config. Point `ssl_certificate*` at your real
   cert (e.g. Let's Encrypt).
2. `edge.yaml` binds `ingress.listen` to `127.0.0.1:8000` — only nginx reaches it.
3. Fill in the agent fingerprint in `edge.yaml`, deploy `agent.yaml`, and start
   both roles.

## Verify

```
nginx -t && systemctl reload nginx
curl https://app.example.com/
```

The edge log shows `ingress.accept host=app.example.com`; a request with an
unknown `Host` gets a `404` from coen (not nginx).
