package doctor

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/metrics"
)

func TestCheckEdgeMetricsBind(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := writeEdgePKI(t, dir)
	cfg := &config.EdgeConfig{
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
	}
	if _, found := findResult(CheckEdge(cfg), "bind: metrics"); found {
		t.Fatal("no metrics check expected when metrics.listen is unset")
	}

	cfg.Metrics.Listen = "127.0.0.1:0"
	if r, found := findResult(CheckEdge(cfg), "bind: metrics"); !found || !r.OK {
		t.Fatalf("want a passing metrics bind check, got found=%v %+v", found, r)
	}

	// A foreign HTTP server holds the port (answers 404, not coen metrics).
	busy := httptest.NewServer(http.NotFoundHandler())
	defer busy.Close()
	cfg.Metrics.Listen = busy.Listener.Addr().String()
	if r, found := findResult(CheckEdge(cfg), "bind: metrics"); !found || r.OK {
		t.Fatalf("want a failing metrics bind check, got found=%v %+v", found, r)
	}
}

func TestCheckAgentMetricsBind(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// A foreign HTTP server holds the port (answers 404, not coen metrics).
	busy := httptest.NewServer(http.NotFoundHandler())
	defer busy.Close()

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{
			Address: "127.0.0.1:1",
			CA:      filepath.Join(dir, "missing-ca.crt"),
			Cert:    filepath.Join(dir, "missing-agent.crt"),
			Key:     filepath.Join(dir, "missing-agent.key"),
		},
		Metrics: config.MetricsConfig{Listen: busy.Listener.Addr().String()},
	}
	// The metrics check runs before the early return on unreadable PKI.
	if r, found := findResult(CheckAgent(cfg), "bind: metrics"); !found || r.OK {
		t.Fatalf("want a failing metrics bind check, got found=%v %+v", found, r)
	}
}

// A foreign process on the metrics port fails the check even while a coen
// daemon is running; a coen metrics endpoint on the port passes it.
func TestCheckMetricsBindDistinguishesOwner(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go_goroutines 7\n"))
	}))
	defer foreign.Close()
	if r := checkMetricsBind(foreign.Listener.Addr().String(), "edge"); r.OK {
		t.Fatalf("a foreign process on the port must fail, got %+v", r)
	}

	ours := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("coen_build_info{role=\"edge\",version=\"dev\"} 1\n"))
	}))
	defer ours.Close()
	r := checkMetricsBind(ours.Listener.Addr().String(), "edge")
	if !r.OK || !strings.Contains(r.Detail, "running coen edge") {
		t.Fatalf("coen's own endpoint on the port must pass, got %+v", r)
	}
	if r := checkMetricsBind(ours.Listener.Addr().String(), "agent"); r.OK {
		t.Fatalf("the edge's endpoint must not satisfy the agent's check, got %+v", r)
	}
	_, port, _ := net.SplitHostPort(ours.Listener.Addr().String())
	if !metrics.ServesRole(":"+port, "edge") {
		t.Fatal("a wildcard address must be probed on loopback")
	}
	if metrics.ServesRole("no-port", "edge") {
		t.Fatal("an unparsable address is not a coen endpoint")
	}
}

// A wildcard IPv6 metrics socket is found on ::1 even when it does not accept
// IPv4, and a named port is resolved before probing.
func TestServesCoenMetricsIPv6AndNamedPort(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("coen_build_info{role=\"agent\",version=\"dev\"} 1\n"))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if !metrics.ServesRole("[::]:"+port, "agent") {
		t.Fatal("an IPv6 wildcard must also be probed on ::1")
	}
	if !metrics.ServesRole("0.0.0.0:"+port, "agent") {
		t.Fatal("0.0.0.0 is dual-stack in Go, so ::1 must be probed too")
	}
	if metrics.ServesRole("127.0.0.1:"+port, "agent") {
		t.Fatal("a concrete IPv4 address must not be probed on ::1")
	}
	if metrics.ServesRole("127.0.0.1:no-such-service", "agent") {
		t.Fatal("an unresolvable named port is not a coen endpoint")
	}
}

func TestBindHint(t *testing.T) {
	op := func(e error) error { return &net.OpError{Op: "listen", Err: &os.SyscallError{Syscall: "bind", Err: e}} }
	if h := bindHint(op(syscall.EACCES), "x"); !strings.Contains(h, "permission denied") {
		t.Errorf("EACCES hint = %q", h)
	}
	if h := bindHint(op(syscall.EADDRNOTAVAIL), "x"); !strings.Contains(h, "not assigned to this host") {
		t.Errorf("EADDRNOTAVAIL hint = %q", h)
	}
	if h := bindHint(op(syscall.EADDRINUSE), "custom"); h != "custom" {
		t.Errorf("fallback hint = %q", h)
	}
	if h := bindHint(op(syscall.EADDRINUSE), ""); !strings.Contains(h, "another process") {
		t.Errorf("default in-use hint = %q", h)
	}
	if h := bindHint(&net.OpError{Op: "listen", Err: &net.DNSError{Err: "no such host", Name: "metrics.internal"}}, "custom"); strings.Contains(h, "another process") || h == "custom" {
		t.Errorf("a resolution error must not get a port-conflict hint, got %q", h)
	}
	// A real unassigned address yields the address hint end to end.
	if r := checkMetricsBind("192.0.2.123:9464", "edge"); r.OK || !strings.Contains(r.Hint, "not assigned") {
		t.Errorf("unassigned address: %+v", r)
	}
}
