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
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
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
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
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
routes:
  - host: "*"
    service: 127.0.0.1:8080
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
		Routes: []EdgeRoute{{Host: "app.example.com", AgentFingerprint: "AA"}},
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
routes:
  - host: "*"
    service: 127.0.0.1:8080
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
routes:
  - host: "*"
    service: 127.0.0.1:8080
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
		t.Fatal("expected validation error for missing routes")
	}
	if !strings.Contains(err.Error(), "at least one route is required") {
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
		Routes: []AgentRoute{{Host: "*", Service: "127.0.0.1:8080"}},
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
		{"no routes", func(c *AgentConfig) { c.Routes = nil }, "at least one route is required"},
		{"route missing service", func(c *AgentConfig) { c.Routes[0].Service = "" }, `route "*": service is required`},
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

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEdgeRoutesAndDropIns(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "edge.yaml")
	writeFile(t, base, `
ingress:
  mode: proxied
  listen: "127.0.0.1:8000"
tunnel:
  listen: ":2636"
  ca: /pki/ca.crt
  cert: /pki/edge.crt
  key: /pki/edge.key
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
`)
	dd := filepath.Join(dir, "edge.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "api.yaml"), `
routes:
  - host: "*.api.example.com"
    agent_fingerprint: "BB"
`)
	c, err := LoadEdge(base)
	if err != nil {
		t.Fatalf("LoadEdge: %v", err)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(c.Routes))
	}
	if c.Ingress.ReadHeaderTimeout.Duration() != 10*time.Second {
		t.Errorf("read_header_timeout default = %v, want 10s", c.Ingress.ReadHeaderTimeout.Duration())
	}
	if c.Drain.Duration() != 15*time.Second {
		t.Errorf("drain_timeout default = %v, want 15s", c.Drain.Duration())
	}
	fps := c.AllowedFingerprints()
	if !fps["AA"] || !fps["BB"] {
		t.Errorf("derived allowlist = %v, want AA and BB", fps)
	}
}

func TestLoadEdgeDuplicateHostAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "edge.yaml")
	writeFile(t, base, `
ingress: { mode: proxied, listen: "127.0.0.1:8000" }
tunnel: { listen: ":2636", ca: /a, cert: /b, key: /c }
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
`)
	dd := filepath.Join(dir, "edge.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "dup.yaml"), `
routes:
  - host: app.example.com
    agent_fingerprint: "BB"
`)
	_, err := LoadEdge(base)
	if err == nil || !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("expected duplicate host error, got %v", err)
	}
}

func TestLoadEdgeStrictDropInRejectsStrayKey(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "edge.yaml")
	writeFile(t, base, `
ingress: { mode: proxied, listen: "127.0.0.1:8000" }
tunnel: { listen: ":2636", ca: /a, cert: /b, key: /c }
routes: [ { host: app.example.com, agent_fingerprint: "AA" } ]
`)
	dd := filepath.Join(dir, "edge.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "bad.yaml"), "ingress: { mode: proxied }\n")
	if _, err := LoadEdge(base); err == nil {
		t.Fatal("expected strict-decode error for stray key in drop-in")
	}
}

func TestLoadAgentRoutes(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "agent.yaml")
	writeFile(t, base, `
edge: { address: "e:2636", ca: /a, cert: /b, key: /c }
routes:
  - host: app.example.com
    service: 127.0.0.1:8080
`)
	c, err := LoadAgent(base)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if len(c.Routes) != 1 || c.Routes[0].Service != "127.0.0.1:8080" {
		t.Fatalf("routes = %+v", c.Routes)
	}
	if c.Drain.Duration() != 15*time.Second {
		t.Errorf("agent drain default = %v, want 15s", c.Drain.Duration())
	}
}

func TestLoadAgentDropIns(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "agent.yaml")
	writeFile(t, base, `
edge: { address: "e:2636", ca: /a, cert: /b, key: /c }
routes:
  - host: app.example.com
    service: 127.0.0.1:8080
`)
	dd := filepath.Join(dir, "agent.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "api.yaml"), `
routes:
  - host: api.example.com
    service: 127.0.0.1:9090
`)
	c, err := LoadAgent(base)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(c.Routes))
	}
}

func TestLoadAgentDuplicateHostAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "agent.yaml")
	writeFile(t, base, `
edge: { address: "e:2636", ca: /a, cert: /b, key: /c }
routes: [ { host: app.example.com, service: 127.0.0.1:8080 } ]
`)
	dd := filepath.Join(dir, "agent.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "dup.yaml"), `
routes: [ { host: app.example.com, service: 127.0.0.1:9090 } ]
`)
	if _, err := LoadAgent(base); err == nil || !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("expected duplicate host error, got %v", err)
	}
}

func TestLoadAgentStrictDropInRejectsStrayKey(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "agent.yaml")
	writeFile(t, base, `
edge: { address: "e:2636", ca: /a, cert: /b, key: /c }
routes: [ { host: app.example.com, service: 127.0.0.1:8080 } ]
`)
	dd := filepath.Join(dir, "agent.d")
	if err := os.Mkdir(dd, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dd, "bad.yaml"), "edge: { address: x }\n")
	if _, err := LoadAgent(base); err == nil {
		t.Fatal("expected strict-decode error for stray key in agent drop-in")
	}
}

func TestEdgeConfigValidateRoutes(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*EdgeConfig)
		want string
	}{
		{"no routes", func(c *EdgeConfig) { c.Routes = nil }, "at least one route"},
		{"missing host", func(c *EdgeConfig) { c.Routes = []EdgeRoute{{AgentFingerprint: "AA"}} }, "host is required"},
		{"missing fingerprint", func(c *EdgeConfig) { c.Routes = []EdgeRoute{{Host: "a.example.com"}} }, "agent_fingerprint is required"},
		{"bad pattern", func(c *EdgeConfig) { c.Routes = []EdgeRoute{{Host: "*.*.com", AgentFingerprint: "AA"}} }, "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validEdgeConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAgentConfigValidateRoutes(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*AgentConfig)
		want string
	}{
		{"missing host", func(c *AgentConfig) { c.Routes = []AgentRoute{{Service: "127.0.0.1:8080"}} }, "host is required"},
		{"bad pattern", func(c *AgentConfig) { c.Routes = []AgentRoute{{Host: "a*b.com", Service: "127.0.0.1:8080"}} }, "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validAgentConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLoadEdgeDropInDirUnreadable(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "edge.yaml")
	writeFile(t, base, `
ingress: { mode: proxied, listen: "127.0.0.1:8000" }
tunnel: { listen: ":2636", ca: /a, cert: /b, key: /c }
routes: [ { host: app.example.com, agent_fingerprint: "AA" } ]
`)
	// edge.d exists but is a regular file, so ReadDir fails with a non-IsNotExist error.
	writeFile(t, filepath.Join(dir, "edge.d"), "not a directory\n")
	if _, err := LoadEdge(base); err == nil || !strings.Contains(err.Error(), "read drop-in dir") {
		t.Fatalf("expected read drop-in dir error, got %v", err)
	}
}
