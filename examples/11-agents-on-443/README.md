# 11. Agents on port 443

Two agents in locked-down networks serve one host through a standalone edge:

- `agent-direct.yaml`: a network that lets connections out only to port 443.
- `agent-proxy.yaml`: a network that reaches the internet only through an HTTP
  proxy, which (like squid by default) allows `CONNECT` only to port 443.

```
agent-direct --mTLS on TCP 443-----------------------------\
                                                            edge :443 (also HTTPS for clients)
agent-proxy --CONNECT edge:443--> proxy --mTLS on TCP 443---/
```

Neither changes the tunnel: it is the same end-to-end mTLS as on port 2636, and
the proxy sees only encrypted bytes. See the README's
[Agents behind restrictive networks](../../README.md#agents-behind-restrictive-networks).

## How the edge tells agents from browsers

With `tunnel.share_ingress: true` the edge looks at the protocols a TLS client
offers (ALPN) before it picks a certificate. Agents from v0.4.0 on offer
`coen/2`; browsers never do. An agent gets the tunnel's mTLS handshake, everyone
else the public certificate. `tunnel.listen` (`:2636` here) still works next to
it, for agents older than v0.4.0; leave it out once every agent dials 443.

## Wire it up

1. Issue the edge certificate for the name the agents dial
   (`coen cert edge --host edge.example.com`), and one certificate per agent.
   `coen cert agent` always writes `agent.crt` and `agent.key`, so rename each
   pair before issuing the next, for example
   `coen cert agent --name agent-direct && mv /etc/coen/pki/agent.crt /etc/coen/pki/agent-direct.crt && mv /etc/coen/pki/agent.key /etc/coen/pki/agent-direct.key`,
   and the same for `agent-proxy`. Put both fingerprints into `edge.yaml`.
2. Deploy `edge.yaml` and the two agent configs. For the proxied agent, set the
   proxy's address and credentials in `edge.proxy` (percent-encode special
   characters in the password), or drop the credentials if the proxy needs
   none. Use `https://` for a proxy that takes TLS.
3. Run `coen doctor --role agent` on each agent host. Behind the proxy it
   resolves the proxy's name rather than the edge's, connects through the proxy,
   and completes the mTLS handshake through it; a refusal shows the proxy's
   answer (`407`: credentials missing or wrong; `403`: the proxy does not allow
   that port).

## Verify

```sh
coen status                  # on each agent: tunnel: connected
coen status                  # on the edge: two agent sessions
curl https://app.example.com/
```

The edge logs each agent's `agent.connected` as usual. An agent offering
`coen/2` without a valid certificate counts as
`coen_tunnel_handshakes_total{result="rejected"}`, as on port 2636.

## Notes

- Behind nginx (proxied mode) the edge never sees the agent's TLS handshake, so
  it cannot share the port; keep `tunnel.listen` reachable there.
- A proxy that intercepts TLS cannot carry the tunnel: the edge would see the
  proxy's certificate, not the agent's.
