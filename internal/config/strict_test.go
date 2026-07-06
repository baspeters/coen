package config

import "testing"

func TestLoadEdgeRejectsUnknownKey(t *testing.T) {
	// A misspelled hardening key must fail loudly, not be silently dropped.
	p := writeTemp(t, "edge.yaml", `
ingress:
  mode: proxied
  listen: 127.0.0.1:8000
  max_conections: 100
tunnel:
  listen: ":2636"
  ca: /a
  cert: /b
  key: /c
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
`)
	if _, err := LoadEdge(p); err == nil {
		t.Fatal("expected an error for a misspelled key in the base edge config")
	}
}

func TestLoadAgentRejectsUnknownKey(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
routes:
  - host: app.example.com
    service: 127.0.0.1:8080
bogus_key: true
`)
	if _, err := LoadAgent(p); err == nil {
		t.Fatal("expected an error for an unknown key in the base agent config")
	}
}
