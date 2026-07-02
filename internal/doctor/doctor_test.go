package doctor

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

func findResult(rs []Result, name string) (Result, bool) {
	for _, r := range rs {
		if r.Name == name {
			return r, true
		}
	}
	return Result{}, false
}

func TestCheckBind(t *testing.T) {
	if r := checkBind("bind", "127.0.0.1:0"); !r.OK {
		t.Fatalf("expected ok, got %+v", r)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	if r := checkBind("bind", ln.Addr().String()); r.OK {
		t.Fatal("expected fail on in-use port")
	}
}

func TestCheckAgentPassesMTLSButDetectsDeadService(t *testing.T) {
	ca, _ := pki.CreateCA()
	dir := t.TempDir()
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
	edgeLn := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	defer edgeLn.Close()
	go func() {
		for {
			c, err := edgeLn.Accept()
			if err != nil {
				return
			}
			go func(cn net.Conn) {
				if tc, ok := cn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()

	// A guaranteed-closed service port.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	cfg := &config.AgentConfig{
		Edge:    config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Service: config.ServiceConfig{Address: deadAddr},
	}
	results := CheckAgent(cfg)
	if mtls, _ := findResult(results, "mtls: handshake"); !mtls.OK {
		t.Fatalf("mtls should pass: %+v", mtls)
	}
	svc, found := findResult(results, "service: reach")
	if !found || svc.OK {
		t.Fatalf("service check should fail (found=%v): %+v", found, svc)
	}
}
