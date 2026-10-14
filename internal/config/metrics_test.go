package config

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestMetricsListenValidation(t *testing.T) {
	cases := []struct {
		listen string
		ok     bool
	}{
		{"", true},
		{"127.0.0.1:9464", true},
		{":9464", true},
		{"[::1]:9464", true},
		{"127.0.0.1", false},
		{"127.0.0.1:", false},
		{"127.0.0.1:94x4", false},
		{"127.0.0.1:0", false},
		{"127.0.0.1:65536", false},
		{"127.0.0.1:http", true}, // named ports resolve like net.Listen
		{"127.0.0.1:no-such-service", false},
		{"not an address", false},
	}
	for _, c := range cases {
		e := validEdgeConfig()
		e.Metrics.Listen = c.listen
		a := validAgentConfig()
		a.Metrics.Listen = c.listen
		for role, err := range map[string]error{"edge": e.Validate(), "agent": a.Validate()} {
			if c.ok && err != nil {
				t.Errorf("%s metrics.listen %q: unexpected error %v", role, c.listen, err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "metrics.listen")) {
				t.Errorf("%s metrics.listen %q: want a metrics.listen error, got %v", role, c.listen, err)
			}
		}
	}
}

func TestLoadEdgeParsesMetrics(t *testing.T) {
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
  - host: "*"
    agent_fingerprint: "AA"
metrics:
  listen: 127.0.0.1:9464
`)
	c, err := LoadEdge(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metrics.Listen != "127.0.0.1:9464" {
		t.Fatalf("metrics.listen = %q", c.Metrics.Listen)
	}
}

func TestLoadAgentRejectsUnknownMetricsKey(t *testing.T) {
	p := writeTemp(t, "agent.yaml", `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
routes:
  - host: "*"
    service: 127.0.0.1:8080
metrics:
  listen: 127.0.0.1:9465
  path: /custom
`)
	if _, err := LoadAgent(p); err == nil {
		t.Fatal("an unknown key under metrics must be rejected")
	}
}

func TestMetricsListenConflicts(t *testing.T) {
	cases := []struct {
		metrics, tunnel, ingress string
		conflict                 bool
	}{
		{"127.0.0.1:9464", ":2636", ":443", false},
		{":2636", ":2636", ":443", true},               // same wildcard port as the tunnel
		{"127.0.0.1:2636", ":2636", ":443", true},      // tunnel's wildcard covers loopback
		{"0.0.0.0:443", ":2636", "10.0.0.1:443", true}, // metrics wildcard covers ingress host
		{"127.0.0.1:8000", ":2636", "127.0.0.1:8000", true},
		{"127.0.0.1:8000", ":2636", "10.0.0.1:8000", false}, // same port, different hosts
		{"[::]:2636", ":2636", ":443", true},
		{"[::1]:2636", "0.0.0.0:2636", ":443", true},       // Go listens dual-stack on 0.0.0.0 too
		{"127.0.0.1:2636", "0.0.0.0:2636", ":443", true},   // IPv4 wildcard covers IPv4 loopback
		{"localhost:2636", "0.0.0.0:2636", ":443", true},   // a name may resolve to IPv4
		{"[::1]:2636", "[::]:2636", ":443", true},          // :: is dual-stack
		{"LOCALHOST:2636", "localhost:2636", ":443", true}, // names compare case-insensitively
		{"127.0.0.1:2636", "[::ffff:127.0.0.1]:2636", ":443", true},
		{":443", ":2636", ":https", true}, // named port resolves to the same 443
	}
	for _, c := range cases {
		e := validEdgeConfig()
		e.Metrics.Listen, e.Tunnel.Listen, e.Ingress.Listen = c.metrics, c.tunnel, c.ingress
		err := e.Validate()
		if c.conflict && (err == nil || !strings.Contains(err.Error(), "conflicts with")) {
			t.Errorf("%+v: want a conflict error, got %v", c, err)
		}
		if !c.conflict && err != nil {
			t.Errorf("%+v: unexpected error %v", c, err)
		}
	}
}

func TestIsWildcardHost(t *testing.T) {
	if got := LoopbackHosts("0.0.0.0"); len(got) != 2 {
		t.Errorf("LoopbackHosts(0.0.0.0) = %v, want both loopbacks", got)
	}
	if got := LoopbackHosts("10.0.0.5"); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Errorf("LoopbackHosts(10.0.0.5) = %v", got)
	}
	for h, want := range map[string]bool{"": true, "0.0.0.0": true, "::": true, "0:0:0:0:0:0:0:0": true, "127.0.0.1": false, "::1": false, "localhost": false} {
		if got := IsWildcardHost(h); got != want {
			t.Errorf("IsWildcardHost(%q) = %v, want %v", h, got, want)
		}
	}
}

// When metrics overlaps both listeners, the error always names the same one.
func TestMetricsConflictReportedDeterministically(t *testing.T) {
	for i := 0; i < 50; i++ {
		e := validEdgeConfig()
		e.Tunnel.Listen, e.Ingress.Listen, e.Metrics.Listen = ":2636", "127.0.0.1:2636", "127.0.0.1:2636"
		if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts with tunnel.listen") {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// Config loading never does a DNS lookup: only IP literals and localhost are
// interpreted, other names compare as written.
func TestHostIPsDoesNoLookup(t *testing.T) {
	if ips, ok := hostIPs("10.1.2.3"); !ok || len(ips) != 1 {
		t.Fatalf("IP literal: %v %v", ips, ok)
	}
	if ips, ok := hostIPs("LocalHost"); !ok || len(ips) != 2 {
		t.Fatalf("localhost: %v %v", ips, ok)
	}
	if _, ok := hostIPs("metrics.internal"); ok {
		t.Fatal("a hostname must not be looked up")
	}
}

func TestAdminSocketReaders(t *testing.T) {
	// Invalid as a whole (no routes) but the socket can still be read.
	e := writeTemp(t, "edge.yaml", "admin:\n  socket: /run/coen/edge.sock\n")
	if s, err := EdgeAdminSocket(e); err != nil || s != "/run/coen/edge.sock" {
		t.Fatalf("EdgeAdminSocket = %q, %v", s, err)
	}
	a := writeTemp(t, "agent.yaml", "admin:\n  socket: /run/coen/agent.sock\n")
	if s, err := AgentAdminSocket(a); err != nil || s != "/run/coen/agent.sock" {
		t.Fatalf("AgentAdminSocket = %q, %v", s, err)
	}
	bad := writeTemp(t, "agent.yaml", "admn:\n  socket: x\n")
	if _, err := AgentAdminSocket(bad); err == nil {
		t.Fatal("a misspelled key must still fail the strict decode")
	}
}

func TestLogLevelSkipsValidation(t *testing.T) {
	// No routes and a conflicting metrics address: invalid for LoadEdge, but
	// the level can still be read for a reload.
	p := writeTemp(t, "edge.yaml", "log:\n  level: debug\nmetrics:\n  listen: \":2636\"\ntunnel:\n  listen: \":2636\"\n")
	if lvl, err := EdgeLogLevel(p); err != nil || lvl != "debug" {
		t.Fatalf("LogLevel = %q, %v", lvl, err)
	}
	if _, err := LoadEdge(p); err == nil {
		t.Fatal("the same file must still fail full validation")
	}
	bad := writeTemp(t, "agent.yaml", "log:\n  levle: debug\n")
	if _, err := AgentLogLevel(bad); err == nil {
		t.Fatal("a misspelled key must still fail the strict decode")
	}
	a := writeTemp(t, "agent.yaml", "log:\n  level: warn\n")
	if lvl, err := AgentLogLevel(a); err != nil || lvl != "warn" {
		t.Fatalf("LogLevel(agent) = %q, %v", lvl, err)
	}
}

func TestAgentMetricsMustNotShareABackendAddress(t *testing.T) {
	a := validAgentConfig() // route service 127.0.0.1:8080
	a.Metrics.Listen = "127.0.0.1:8080"
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts with the service") {
		t.Fatalf("want a service conflict, got %v", err)
	}
	a.Metrics.Listen = "0.0.0.0:8080" // wildcard covers the backend's loopback port
	if err := a.Validate(); err == nil {
		t.Fatal("a wildcard on the backend's port must conflict")
	}
	a.Metrics.Listen = "127.0.0.1:9465"
	if err := a.Validate(); err != nil {
		t.Fatalf("a distinct port must pass: %v", err)
	}
}

// Only backends on this host can collide with the agent's metrics listener.
func TestServiceOnMetricsSocket(t *testing.T) {
	oldAddrs := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	defer func() { interfaceAddrs = oldAddrs }()
	cases := []struct {
		metrics, service string
		want             bool
	}{
		{"0.0.0.0:9100", "10.0.0.20:9100", false},  // remote backend on another box
		{"0.0.0.0:9100", "10.0.0.5:9100", true},    // this host's own address
		{"0.0.0.0:9100", "127.0.0.1:9100", true},   // loopback
		{"127.0.0.1:9100", "10.0.0.5:9100", false}, // metrics only on loopback
		{"127.0.0.1:9100", "127.0.0.1:9100", true},
		{"127.0.0.1:9100", "127.0.0.1:8080", false}, // different port
		{"10.0.0.5:9100", "0.0.0.0:9100", false},    // dialing 0.0.0.0 reaches loopback, not 10.0.0.5
		{"127.0.0.1:9100", "0.0.0.0:9100", true},    // ... which a loopback listener answers
		{"0.0.0.0:9100", "unresolvable.invalid:9100", false},
		{"127.0.0.1:9100", ":9100", true}, // an empty host dials this machine
		{":9100", ":9100", true},
	}
	for _, c := range cases {
		if got := serviceOnMetricsSocket(c.metrics, c.service, localIPs()); got != c.want {
			t.Errorf("serviceOnMetricsSocket(%q, %q) = %v, want %v", c.metrics, c.service, got, c.want)
		}
	}
	a := validAgentConfig()
	a.Routes = []AgentRoute{{Host: "*", Service: "10.0.0.20:9100"}}
	a.Metrics.Listen = "0.0.0.0:9100"
	if err := a.Validate(); err != nil {
		t.Fatalf("a remote backend on the metrics port must be accepted: %v", err)
	}
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("no interfaces") }
	if serviceOnMetricsSocket("0.0.0.0:9100", "10.0.0.5:9100", localIPs()) {
		t.Fatal("without interface data, a non-loopback address is treated as remote")
	}
}
