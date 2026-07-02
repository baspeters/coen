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
		Edge:   config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes: []config.AgentRoute{{Host: "*", Service: deadAddr}},
	}
	results := CheckAgent(cfg)
	if mtls, _ := findResult(results, "mtls: handshake"); !mtls.OK {
		t.Fatalf("mtls should pass: %+v", mtls)
	}
	svc, found := findResult(results, "service: reach *")
	if !found || svc.OK {
		t.Fatalf("service check should fail (found=%v): %+v", found, svc)
	}
}

func TestCheckFileMissing(t *testing.T) {
	r := checkFile("pki: ca", "/nonexistent/path/for/coen/tests/ca.crt")
	if r.OK {
		t.Fatalf("expected failure for missing file, got %+v", r)
	}
	if r.Hint == "" {
		t.Fatal("expected a hint on failure")
	}
}

// writeEdgePKI creates a throwaway CA plus an edge server keypair issued by
// it, writes them under dir, and returns their paths.
func writeEdgePKI(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	caPath = filepath.Join(dir, "ca.crt")
	certPath = filepath.Join(dir, "edge.crt")
	keyPath = filepath.Join(dir, "edge.key")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return caPath, certPath, keyPath
}

func TestCheckEdgeProxiedAllPass(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath, certPath, keyPath := writeEdgePKI(t, dir)

	cfg := &config.EdgeConfig{
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
	}
	results := CheckEdge(cfg)
	for _, r := range results {
		if !r.OK {
			t.Errorf("expected all checks to pass, got failing result: %+v", r)
		}
	}
	if _, found := findResult(results, "pki: public cert"); found {
		t.Fatal("proxied mode should not run the public cert check")
	}
}

func TestCheckEdgeStandaloneValidPublicCert(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath, certPath, keyPath := writeEdgePKI(t, dir)

	pubCA, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	pubCertPEM, pubKeyPEM, err := pubCA.IssueServer("example.com")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	pubCertPath := filepath.Join(dir, "pub.crt")
	pubKeyPath := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(pubCertPath, pubCertPEM, 0o600); err != nil {
		t.Fatalf("write pub cert: %v", err)
	}
	if err := os.WriteFile(pubKeyPath, pubKeyPEM, 0o600); err != nil {
		t.Fatalf("write pub key: %v", err)
	}

	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Ingress: config.IngressConfig{
			Mode:   "standalone",
			Listen: "127.0.0.1:0",
			TLS:    config.TLSFiles{Cert: pubCertPath, Key: pubKeyPath},
		},
	}
	results := CheckEdge(cfg)
	r, found := findResult(results, "pki: public cert")
	if !found || !r.OK {
		t.Fatalf("expected public cert check to pass, found=%v %+v", found, r)
	}
}

func TestCheckEdgeStandaloneMissingPublicCert(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath, certPath, keyPath := writeEdgePKI(t, dir)

	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Ingress: config.IngressConfig{
			Mode:   "standalone",
			Listen: "127.0.0.1:0",
			TLS: config.TLSFiles{
				Cert: filepath.Join(dir, "missing-pub.crt"),
				Key:  filepath.Join(dir, "missing-pub.key"),
			},
		},
	}
	results := CheckEdge(cfg)
	r, found := findResult(results, "pki: public cert")
	if !found || r.OK {
		t.Fatalf("expected public cert check to fail, found=%v %+v", found, r)
	}
	if r.Hint == "" {
		t.Fatal("expected a hint on failure")
	}
}

func TestCheckEdgeBindFailure(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath, certPath, keyPath := writeEdgePKI(t, dir)

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer held.Close()
	heldAddr := held.Addr().String()

	t.Run("tunnel", func(t *testing.T) {
		cfg := &config.EdgeConfig{
			Tunnel:  config.TunnelServerConfig{Listen: heldAddr, CA: caPath, Cert: certPath, Key: keyPath},
			Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
		}
		results := CheckEdge(cfg)
		r, found := findResult(results, "bind: tunnel")
		if !found || r.OK {
			t.Fatalf("expected tunnel bind failure, found=%v %+v", found, r)
		}
	})

	t.Run("ingress", func(t *testing.T) {
		cfg := &config.EdgeConfig{
			Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
			Ingress: config.IngressConfig{Mode: "proxied", Listen: heldAddr},
		}
		results := CheckEdge(cfg)
		r, found := findResult(results, "bind: ingress")
		if !found || r.OK {
			t.Fatalf("expected ingress bind failure, found=%v %+v", found, r)
		}
	})
}

func TestCheckEdgeMissingCertFiles(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{
			Listen: "127.0.0.1:0",
			CA:     filepath.Join(dir, "missing-ca.crt"),
			Cert:   filepath.Join(dir, "missing-edge.crt"),
			Key:    filepath.Join(dir, "missing-edge.key"),
		},
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
	}
	results := CheckEdge(cfg)
	for _, name := range []string{"pki: ca", "pki: edge cert", "pki: edge key", "pki: ca parse", "pki: edge keypair"} {
		r, found := findResult(results, name)
		if !found || r.OK {
			t.Fatalf("expected %q to fail, found=%v %+v", name, found, r)
		}
	}
}

func TestCheckAgentMissingPKIFiles(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{
			Address: "127.0.0.1:1",
			CA:      filepath.Join(dir, "missing-ca.crt"),
			Cert:    filepath.Join(dir, "missing-agent.crt"),
			Key:     filepath.Join(dir, "missing-agent.key"),
		},
	}
	results := CheckAgent(cfg)
	for _, name := range []string{"pki: ca", "pki: client cert", "pki: client key", "pki: ca parse"} {
		r, found := findResult(results, name)
		if !found || r.OK {
			t.Fatalf("expected %q to fail, found=%v %+v", name, found, r)
		}
	}
	if len(results) != 4 {
		t.Fatalf("expected an early return with 4 results, got %d: %+v", len(results), results)
	}
}

func TestCheckAgentInvalidCAPEM(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(caPath, []byte("not a real cert"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("not a real cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{Address: "127.0.0.1:1", CA: caPath, Cert: certPath, Key: keyPath},
	}
	results := CheckAgent(cfg)
	r, found := findResult(results, "pki: ca parse")
	if !found || r.OK {
		t.Fatalf("expected ca parse failure, found=%v %+v", found, r)
	}
	if r.Hint == "" {
		t.Fatal("expected a hint on failure")
	}
	if len(results) != 4 {
		t.Fatalf("expected an early return after invalid CA PEM, got %d results: %+v", len(results), results)
	}
}

func TestCheckAgentBadClientKeypair(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{Address: deadAddr, CA: caPath, Cert: certPath, Key: keyPath},
	}
	results := CheckAgent(cfg)
	r, found := findResult(results, "pki: client keypair")
	if !found || r.OK {
		t.Fatalf("expected client keypair failure, found=%v %+v", found, r)
	}
}

func TestCheckAgentDNSResolveFailure(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	acPEM, akPEM, err := ca.IssueClient("agent-1")
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	if err := os.WriteFile(certPath, acPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, akPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{Address: "no.such.host.invalid:2636", CA: caPath, Cert: certPath, Key: keyPath},
	}
	results := CheckAgent(cfg)
	r, found := findResult(results, "dns: resolve edge")
	if !found || r.OK {
		t.Fatalf("expected dns resolve failure, found=%v %+v", found, r)
	}
}

func TestCheckAgentMatchingFingerprintPin(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	acPEM, akPEM, err := ca.IssueClient("agent-1")
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	if err := os.WriteFile(certPath, acPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, akPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ecPEM, ekPEM, err := ca.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	edgeCert, err := tls.X509KeyPair(ecPEM, ekPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool, err := pki.CertPoolFromPEM(ca.CertPEM())
	if err != nil {
		t.Fatalf("CertPoolFromPEM: %v", err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
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

	fp, err := pki.FingerprintPEM(ecPEM)
	if err != nil {
		t.Fatalf("FingerprintPEM: %v", err)
	}

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	cfg := &config.AgentConfig{
		Edge:   config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath, EdgeFingerprint: fp},
		Routes: []config.AgentRoute{{Host: "*", Service: deadAddr}},
	}
	results := CheckAgent(cfg)
	if mtls, _ := findResult(results, "mtls: handshake"); !mtls.OK {
		t.Fatalf("mtls should pass: %+v", mtls)
	}
	if pin, found := findResult(results, "mtls: pin"); found {
		t.Fatalf("expected no pin failure for a matching fingerprint, got %+v", pin)
	}
}
