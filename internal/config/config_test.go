package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestDurationUnmarshalYAMLValid(t *testing.T) {
	var wrapper struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal([]byte("d: 1s\n"), &wrapper); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if wrapper.D.Duration() != time.Second {
		t.Fatalf("D = %v, want 1s", wrapper.D.Duration())
	}
}

func TestDurationUnmarshalYAMLInvalid(t *testing.T) {
	var wrapper struct {
		D Duration `yaml:"d"`
	}
	err := yaml.Unmarshal([]byte("d: not-a-duration\n"), &wrapper)
	if err == nil {
		t.Fatal("expected error for invalid duration string")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDurationUnmarshalYAMLNonScalar(t *testing.T) {
	var wrapper struct {
		D Duration `yaml:"d"`
	}
	err := yaml.Unmarshal([]byte("d:\n  - 1\n  - 2\n"), &wrapper)
	if err == nil {
		t.Fatal("expected error for non-scalar duration node")
	}
}

func TestLoadEdgeMissingFile(t *testing.T) {
	_, err := LoadEdge(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadEdgeInvalidYAML(t *testing.T) {
	p := writeTemp(t, "edge.yaml", "ingress: [this is not valid yaml\n")
	_, err := LoadEdge(p)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func validEdgeConfig() EdgeConfig {
	return EdgeConfig{
		Ingress: IngressConfig{
			Mode:   "proxied",
			Listen: ":8080",
		},
		Tunnel: TunnelServerConfig{
			Listen: ":2636",
			CA:     "/a",
			Cert:   "/b",
			Key:    "/c",
		},
	}
}

func TestEdgeConfigValidateProxiedOK(t *testing.T) {
	c := validEdgeConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEdgeConfigValidateStandaloneRequiresCertAndKey(t *testing.T) {
	tests := []struct {
		name string
		cert string
		key  string
	}{
		{"missing cert", "", "/key"},
		{"missing key", "/cert", ""},
		{"missing both", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validEdgeConfig()
			c.Ingress.Mode = "standalone"
			c.Ingress.TLS.Cert = tt.cert
			c.Ingress.TLS.Key = tt.key
			err := c.Validate()
			if err == nil {
				t.Fatal("expected error for missing standalone TLS cert/key")
			}
			if !strings.Contains(err.Error(), "ingress.tls.cert and ingress.tls.key are required") {
				t.Fatalf("unexpected error message: %v", err)
			}
		})
	}
}

func TestEdgeConfigValidateStandaloneWithCertAndKeyOK(t *testing.T) {
	c := validEdgeConfig()
	c.Ingress.Mode = "standalone"
	c.Ingress.TLS.Cert = "/cert"
	c.Ingress.TLS.Key = "/key"
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEdgeConfigValidateBadMode(t *testing.T) {
	c := validEdgeConfig()
	c.Ingress.Mode = "bogus"
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error for bad ingress mode")
	}
	if !strings.Contains(err.Error(), `got "bogus"`) {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestEdgeConfigValidateMissingIngressListen(t *testing.T) {
	c := validEdgeConfig()
	c.Ingress.Listen = ""
	err := c.Validate()
	if err == nil || err.Error() != "ingress.listen is required" {
		t.Fatalf("err = %v, want %q", err, "ingress.listen is required")
	}
}

func TestEdgeConfigValidateTunnelFieldsRequired(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *EdgeConfig)
		wantErr string
	}{
		{"missing tunnel.listen", func(c *EdgeConfig) { c.Tunnel.Listen = "" }, "tunnel.listen is required"},
		{"missing tunnel.ca", func(c *EdgeConfig) { c.Tunnel.CA = "" }, "tunnel.ca is required"},
		{"missing tunnel.cert", func(c *EdgeConfig) { c.Tunnel.Cert = "" }, "tunnel.cert is required"},
		{"missing tunnel.key", func(c *EdgeConfig) { c.Tunnel.Key = "" }, "tunnel.key is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validEdgeConfig()
			tt.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadAgentMissingFile(t *testing.T) {
	_, err := LoadAgent(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadAgentInvalidYAML(t *testing.T) {
	p := writeTemp(t, "agent.yaml", "edge: [this is not valid yaml\n")
	_, err := LoadAgent(p)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadAgentDefaultBackoffWhenOmitted(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
service:
  address: 127.0.0.1:8080
`)
	c, err := LoadAgent(p)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if c.Reconnect.MinBackoff.Duration() != time.Second {
		t.Fatalf("MinBackoff = %v, want default 1s", c.Reconnect.MinBackoff.Duration())
	}
	if c.Reconnect.MaxBackoff.Duration() != 30*time.Second {
		t.Fatalf("MaxBackoff = %v, want default 30s", c.Reconnect.MaxBackoff.Duration())
	}
}

func TestLoadAgentExplicitBackoffValuesPreserved(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
service:
  address: 127.0.0.1:8080
reconnect:
  min_backoff: 5s
  max_backoff: 60s
`)
	c, err := LoadAgent(p)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if c.Reconnect.MinBackoff.Duration() != 5*time.Second {
		t.Fatalf("MinBackoff = %v, want 5s", c.Reconnect.MinBackoff.Duration())
	}
	if c.Reconnect.MaxBackoff.Duration() != 60*time.Second {
		t.Fatalf("MaxBackoff = %v, want 60s", c.Reconnect.MaxBackoff.Duration())
	}
}

func TestLoadAgentValidationError(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
`)
	_, err := LoadAgent(p)
	if err == nil {
		t.Fatal("expected validation error for missing service.address")
	}
	if !strings.Contains(err.Error(), "service.address is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func validAgentConfig() AgentConfig {
	return AgentConfig{
		Edge: EdgeRef{
			Address: "edge.example.com:2636",
			CA:      "/a",
			Cert:    "/b",
			Key:     "/c",
		},
		Service: ServiceConfig{
			Address: "127.0.0.1:8080",
		},
	}
}

func TestAgentConfigValidateOK(t *testing.T) {
	c := validAgentConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgentConfigValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *AgentConfig)
		wantErr string
	}{
		{"missing edge.address", func(c *AgentConfig) { c.Edge.Address = "" }, "edge.address is required"},
		{"missing edge.ca", func(c *AgentConfig) { c.Edge.CA = "" }, "edge.ca is required"},
		{"missing edge.cert", func(c *AgentConfig) { c.Edge.Cert = "" }, "edge.cert is required"},
		{"missing edge.key", func(c *AgentConfig) { c.Edge.Key = "" }, "edge.key is required"},
		{"missing service.address", func(c *AgentConfig) { c.Service.Address = "" }, "service.address is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validAgentConfig()
			tt.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}
