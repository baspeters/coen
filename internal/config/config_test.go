package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadEdgeValid(t *testing.T) {
	p := writeTemp(t, "edge.yaml", `
ingress:
  mode: standalone
  listen: ":443"
  tls:
    cert: /etc/coen/certs/public.crt
    key: /etc/coen/certs/public.key
tunnel:
  listen: ":2636"
  ca: /etc/coen/pki/ca.crt
  cert: /etc/coen/pki/edge.crt
  key: /etc/coen/pki/edge.key
log:
  level: info
  format: text
admin:
  socket: /run/coen/edge.sock
`)
	c, err := LoadEdge(p)
	if err != nil {
		t.Fatalf("LoadEdge: %v", err)
	}
	if c.Ingress.Mode != "standalone" || c.Tunnel.Listen != ":2636" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestLoadEdgeProxiedNeedsNoTLS(t *testing.T) {
	p := writeTemp(t, "edge.yaml", `
ingress:
  mode: proxied
  listen: 127.0.0.1:8000
tunnel:
  listen: ":2636"
  ca: /a
  cert: /b
  key: /c
`)
	if _, err := LoadEdge(p); err != nil {
		t.Fatalf("proxied should not require tls: %v", err)
	}
}

func TestLoadEdgeStandaloneRequiresTLS(t *testing.T) {
	p := writeTemp(t, "edge.yaml", `
ingress:
  mode: standalone
  listen: ":443"
tunnel:
  listen: ":2636"
  ca: /a
  cert: /b
  key: /c
`)
	if _, err := LoadEdge(p); err == nil {
		t.Fatal("expected error: standalone requires tls cert/key")
	}
}

func TestLoadEdgeRejectsBadMode(t *testing.T) {
	p := writeTemp(t, "edge.yaml", "ingress:\n  mode: bogus\n  listen: \":443\"\ntunnel:\n  listen: \":2636\"\n  ca: /a\n  cert: /b\n  key: /c\n")
	if _, err := LoadEdge(p); err == nil {
		t.Fatal("expected error for bad ingress mode")
	}
}

func TestLoadAgentDefaultsAndDuration(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
service:
  address: 127.0.0.1:8080
reconnect:
  min_backoff: 2s
`)
	c, err := LoadAgent(p)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if c.Reconnect.MinBackoff.Duration() != 2*time.Second {
		t.Fatalf("min_backoff = %v", c.Reconnect.MinBackoff.Duration())
	}
	if c.Reconnect.MaxBackoff.Duration() != 30*time.Second {
		t.Fatalf("expected default max_backoff 30s, got %v", c.Reconnect.MaxBackoff.Duration())
	}
}
