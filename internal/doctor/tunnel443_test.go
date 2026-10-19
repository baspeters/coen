package doctor

import (
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/netx/proxytest"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

// An edge whose agents come in on the ingress has no tunnel port to bind.
func TestCheckEdgeSharedIngress(t *testing.T) {
	caPath, certPath, keyPath := writeEdgePKI(t, t.TempDir())
	cfg := &config.EdgeConfig{
		Tunnel:  config.TunnelServerConfig{ShareIngress: true, CA: caPath, Cert: certPath, Key: keyPath},
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
	}
	results := CheckEdge(cfg)
	if _, found := findResult(results, "bind: tunnel"); found {
		t.Fatal("no tunnel.listen: nothing to bind")
	}
	if r, found := findResult(results, "tunnel: shared ingress"); !found || !r.OK || !strings.Contains(r.Detail, "127.0.0.1:0") {
		t.Fatalf("got %+v", r)
	}
	cfg.Tunnel.Listen = "127.0.0.1:0"
	if r, found := findResult(CheckEdge(cfg), "bind: tunnel"); !found || !r.OK {
		t.Fatalf("both: the tunnel port is still checked, got %+v", r)
	}
}

// agentAndEdge writes an agent's PKI and runs an edge TLS listener that
// completes the tunnel handshake.
func agentAndEdge(t *testing.T) (*config.AgentConfig, string) {
	t.Helper()
	dir := t.TempDir()
	ca, _ := pki.CreateCA()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, acPEM, 0o600)
	_ = os.WriteFile(keyPath, akPEM, 0o600)
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	ln := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	return &config.AgentConfig{Edge: config.EdgeRef{Address: ln.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath}}, ln.Addr().String()
}

func TestCheckAgentThroughProxy(t *testing.T) {
	cfg, edgeAddr := agentAndEdge(t)
	p := proxytest.Start(t, proxytest.Options{User: "a", Password: "b"})
	cfg.Edge.Proxy = p.URL.String()
	results := CheckAgent(cfg)
	if r, _ := findResult(results, "dns: resolve proxy"); !r.OK {
		t.Fatalf("dns: %+v", r)
	}
	if _, found := findResult(results, "dns: resolve edge"); found {
		t.Fatal("behind a proxy the edge's name is the proxy's to resolve")
	}
	if r, _ := findResult(results, "net: tcp reach"); !r.OK || !strings.Contains(r.Detail, "through proxy http://a:xxxxx@") {
		t.Fatalf("reach: %+v (credentials must be redacted)", r)
	}
	if r, _ := findResult(results, "mtls: handshake"); !r.OK {
		t.Fatalf("mtls: %+v", r)
	}
	if tg := p.Targets(); len(tg) != 1 || tg[0] != edgeAddr {
		t.Fatalf("one CONNECT for both checks, to the edge: %v", tg)
	}

	// A proxy that refuses the port: the hint says why.
	strict := proxytest.Start(t, proxytest.Options{AllowPorts: []string{"443"}})
	cfg.Edge.Proxy = strict.URL.String()
	if r, _ := findResult(CheckAgent(cfg), "net: tcp reach"); r.OK || !strings.Contains(r.Detail, "403") || !strings.Contains(r.Hint, "many allow only 443") {
		t.Fatalf("got %+v", r)
	}

	// Missing credentials: the hint says so.
	cfg.Edge.Proxy = (&url.URL{Scheme: "http", Host: p.URL.Host}).String()
	if r, _ := findResult(CheckAgent(cfg), "net: tcp reach"); r.OK || !strings.Contains(r.Hint, "user:password") {
		t.Fatalf("got %+v", r)
	}

	// A proxy whose name does not resolve.
	cfg.Edge.Proxy = "http://proxy.invalid:3128"
	if r, _ := findResult(CheckAgent(cfg), "dns: resolve proxy"); r.OK {
		t.Fatalf("got %+v", r)
	}
}
