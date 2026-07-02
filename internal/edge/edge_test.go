package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// fingerprintOf computes the client-cert fingerprint the edge would derive for
// a route, from an issued cert PEM.
func fingerprintOf(t *testing.T, certPEM []byte) string {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("decode cert PEM")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pki.Fingerprint(leaf)
}

// agentsConnected reports how many agents the edge state currently shows.
func agentsConnected(e *Edge) int { return len(e.state.Snapshot().Agents) }

func newTestEdge(t *testing.T) (e *Edge, tunLn, ingressLn net.Listener, agentTLS *tls.Config) {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(certPath, ecPEM, 0o600)
	_ = os.WriteFile(keyPath, ekPEM, 0o600)

	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	agentFP := fingerprintOf(t, acPEM)

	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Routes:  []config.EdgeRoute{{Host: "*", AgentFingerprint: agentFP}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err = New(cfg, log, &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn = tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	ingressLn, _ = net.Listen("tcp", "127.0.0.1:0")

	agentCert, _ := tls.X509KeyPair(acPEM, akPEM)
	agentTLS = tunnel.ClientTLSConfig(pool, agentCert, "127.0.0.1")
	return e, tunLn, ingressLn, agentTLS
}

func TestEdgeReturns502WithoutAgent(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	conn, err := net.Dial("tcp", ingressLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "502 Bad Gateway") {
		t.Fatalf("expected 502, got %q", resp)
	}
}

func TestEdgeRoutesToAgent(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	// Stub agent: accept streams, read preamble, reply HTTP 200.
	go func() {
		raw, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
		if err != nil {
			return
		}
		sess, err := tunnel.ClientSession(raw)
		if err != nil {
			return
		}
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				p, err := tunnel.ReadPreamble(s)
				if err != nil || p.ConnID == "" {
					return
				}
				_, _ = bufio.NewReader(s).ReadString('\n')
				_, _ = io.WriteString(s, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(stream)
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for e.reg.size() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("agent never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("tcp", ingressLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "200 OK") {
		t.Fatalf("expected 200, got %q", resp)
	}
}

// newTestEdgeWithAllowlist is like newTestEdge but derives the edge's fingerprint
// allowlist from routes owned by the given fingerprints (the edge-authoritative
// model), so an agent whose fingerprint is absent is rejected.
func newTestEdgeWithAllowlist(t *testing.T, allowed []string) (e *Edge, tunLn, ingressLn net.Listener, agentTLS *tls.Config) {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(certPath, ecPEM, 0o600)
	_ = os.WriteFile(keyPath, ekPEM, 0o600)

	routes := make([]config.EdgeRoute, len(allowed))
	for i, fp := range allowed {
		host := "*"
		if i > 0 {
			host = fmt.Sprintf("h%d.example.com", i)
		}
		routes[i] = config.EdgeRoute{Host: host, AgentFingerprint: fp}
	}
	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
		Routes:  routes,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err = New(cfg, log, &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn = tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	ingressLn, _ = net.Listen("tcp", "127.0.0.1:0")

	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	agentCert, _ := tls.X509KeyPair(acPEM, akPEM)
	agentTLS = tunnel.ClientTLSConfig(pool, agentCert, "127.0.0.1")
	return e, tunLn, ingressLn, agentTLS
}

func TestEdgeRejectsAgentNotOnAllowlist(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdgeWithAllowlist(t, []string{"SHA256:bogus"})
	defer tunLn.Close()
	defer ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	// Stub agent: dial and attempt to establish a session. The edge should
	// reject it before ever registering a session.
	go func() {
		raw, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
		if err != nil {
			return
		}
		sess, err := tunnel.ClientSession(raw)
		if err != nil {
			return
		}
		<-sess.CloseChan()
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if e.reg.size() != 0 {
			t.Fatal("agent was admitted despite not being on the allow-list")
		}
		if agentsConnected(e) > 0 {
			t.Fatal("state reports connected despite agent not being on the allow-list")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.reg.size() != 0 {
		t.Fatal("agent was admitted despite not being on the allow-list")
	}
	if agentsConnected(e) > 0 {
		t.Fatal("state reports connected despite agent not being on the allow-list")
	}
}

func TestEdgeReconnectDoesNotFlipStateToDisconnected(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	dialAgent := func() *yamux.Session {
		raw, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := tunnel.ClientSession(raw)
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}

	// Stub agent #1: connect and stay idle until the edge closes its session
	// (which happens when agent #2 replaces it).
	sess1 := dialAgent()
	defer sess1.Close()
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		<-sess1.CloseChan()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for e.reg.size() == 0 || agentsConnected(e) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("agent #1 never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	firstSession := e.reg.any()

	// Stub agent #2: connect, replacing agent #1's session (the edge closes
	// #1's session as part of admitting #2).
	sess2 := dialAgent()
	defer sess2.Close()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		<-sess2.CloseChan()
	}()

	deadline = time.Now().Add(2 * time.Second)
	for {
		cur := e.reg.any()
		if cur != nil && cur != firstSession {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent #2 never registered (session did not change)")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Poll for ~1s: connected state must never flip false, and the session
	// must remain registered, even though agent #1's goroutine is unwinding
	// from its now-closed session.
	pollDeadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(pollDeadline) {
		if agentsConnected(e) == 0 {
			t.Fatal("TunnelConnected flipped false after agent #2 replaced agent #1")
		}
		if e.reg.any() == nil {
			t.Fatal("session became nil after agent #2 replaced agent #1")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done1
	<-done2
}

func TestEdgeClosesAgentSessionOnShutdown(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	// Stub agent: connect, establish a session, stay idle until the edge closes it.
	go func() {
		raw, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
		if err != nil {
			return
		}
		sess, err := tunnel.ClientSession(raw)
		if err != nil {
			return
		}
		<-sess.CloseChan()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for e.reg.size() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("agent never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	deadline = time.Now().Add(2 * time.Second)
	for agentsConnected(e) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("edge did not tear down the agent session / clear state on shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestListenIngressProxiedReturnsPlainListener(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()

	ln, err := e.listenIngress()
	if err != nil {
		t.Fatalf("listenIngress: %v", err)
	}
	defer ln.Close()

	if _, ok := ln.(*net.TCPListener); !ok {
		t.Fatalf("expected a plain *net.TCPListener in proxied mode, got %T", ln)
	}
}

func TestListenIngressStandaloneReturnsTLSListener(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	tunCertPath := filepath.Join(dir, "tunnel.crt")
	tunKeyPath := filepath.Join(dir, "tunnel.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	tcPEM, tkPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(tunCertPath, tcPEM, 0o600)
	_ = os.WriteFile(tunKeyPath, tkPEM, 0o600)

	pubCertPath := filepath.Join(dir, "public.crt")
	pubKeyPath := filepath.Join(dir, "public.key")
	pcPEM, pkPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(pubCertPath, pcPEM, 0o600)
	_ = os.WriteFile(pubKeyPath, pkPEM, 0o600)

	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{
			Mode:   "standalone",
			Listen: "127.0.0.1:0",
			TLS:    config.TLSFiles{Cert: pubCertPath, Key: pubKeyPath},
		},
		Tunnel: config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: tunCertPath, Key: tunKeyPath},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := New(cfg, log, &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := e.listenIngress()
	if err != nil {
		t.Fatalf("listenIngress: %v", err)
	}
	defer ln.Close()

	// Prove the listener actually speaks TLS by completing a real handshake
	// against it from a client that trusts the issuing CA.
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			srvErr <- errors.New("accepted conn is not *tls.Conn")
			return
		}
		srvErr <- tlsConn.Handshake()
	}()

	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("client dial/handshake: %v", err)
	}
	defer clientConn.Close()

	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not complete handshake")
	}
}

func TestListenIngressUnknownModeReturnsError(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()

	e.cfg.Ingress.Mode = "bogus"
	ln, err := e.listenIngress()
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected error for unknown ingress mode")
	}
}

func TestRunStartsAndStopsOnCancel(t *testing.T) {
	e, preTunLn, preIngressLn, _ := newTestEdge(t)
	// newTestEdge builds e.cfg with ephemeral 127.0.0.1:0 listen addresses and
	// real temp-file PKI already; Run() binds its own listeners from that
	// config, so the pre-built listeners here are unused.
	_ = preTunLn.Close()
	_ = preIngressLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- e.Run(ctx) }()

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of context cancellation")
	}
}

func TestServeAgentClosesNonTLSConn(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()

	serverSide, testSide := net.Pipe()
	defer testSide.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.serveAgent(serverSide)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveAgent did not return for a non-TLS conn")
	}

	// serveAgent should have closed its side; the peer must observe that.
	if _, err := testSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected read on peer to fail after serveAgent closed the non-TLS conn")
	}
}

func TestServeAgentFailedHandshakeNoClientCert(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()

	if got := e.state.Snapshot().HandshakeFail; got != 0 {
		t.Fatalf("expected handshake fail counter to start at 0, got %d", got)
	}

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := tunLn.Accept()
		if err != nil {
			return
		}
		e.serveAgent(conn)
	}()

	// Client presents no certificate; the server requires one and must fail
	// the handshake.
	clientConn, dialErr := tls.Dial("tcp", tunLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if dialErr == nil {
		_ = clientConn.Close()
	}

	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serveAgent did not return after a failed handshake")
	}

	if e.reg.size() != 0 {
		t.Fatal("session should remain nil after a failed handshake")
	}
	if got := e.state.Snapshot().HandshakeFail; got != 1 {
		t.Fatalf("expected handshake fail counter = 1, got %d", got)
	}
}

func TestNewMissingCAFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{CA: filepath.Join(dir, "does-not-exist.crt")},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(cfg, log, &obs.State{}); err == nil {
		t.Fatal("expected error for a missing tunnel CA file")
	}
}

func TestNewInvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("not a valid PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.EdgeConfig{Tunnel: config.TunnelServerConfig{CA: caPath}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(cfg, log, &obs.State{}); err == nil {
		t.Fatal("expected error for an invalid CA PEM file")
	}
}

// TestRunFailsWhenTunnelListenAddrInUse exercises Run's first error branch:
// the tunnel TLS listener fails to bind because something else already holds
// the port. Run must return that error without ever reaching Serve.
func TestRunFailsWhenTunnelListenAddrInUse(t *testing.T) {
	e, preTunLn, preIngressLn, _ := newTestEdge(t)
	// newTestEdge's pre-built listeners are unused here; Run binds its own
	// from e.cfg.
	_ = preTunLn.Close()
	_ = preIngressLn.Close()

	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	e.cfg.Tunnel.Listen = conflict.Addr().String()

	if err := e.Run(context.Background()); err == nil {
		t.Fatal("expected Run to fail when the tunnel listen address is already in use")
	}
}

// TestRunFailsWhenIngressCertMissing exercises Run's second error branch: the
// tunnel listener binds fine (valid PKI), but standalone ingress mode points
// at a public cert/key pair that doesn't exist, so listenIngress fails and
// Run must close the tunnel listener and return the error before ever
// calling Serve.
func TestRunFailsWhenIngressCertMissing(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	tunCertPath := filepath.Join(dir, "tunnel.crt")
	tunKeyPath := filepath.Join(dir, "tunnel.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	tcPEM, tkPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(tunCertPath, tcPEM, 0o600)
	_ = os.WriteFile(tunKeyPath, tkPEM, 0o600)

	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{
			Mode:   "standalone",
			Listen: "127.0.0.1:0",
			TLS: config.TLSFiles{
				Cert: filepath.Join(dir, "missing-public.crt"),
				Key:  filepath.Join(dir, "missing-public.key"),
			},
		},
		Tunnel: config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: tunCertPath, Key: tunKeyPath},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := New(cfg, log, &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := e.Run(context.Background()); err == nil {
		t.Fatal("expected Run to fail when the standalone ingress cert/key files are missing")
	}
}

func TestNewMismatchedCertKeyPair(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)

	certPEM, _, _ := ca.IssueServer("127.0.0.1")
	_, otherKeyPEM, _ := ca.IssueServer("127.0.0.1")

	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	_ = os.WriteFile(certPath, certPEM, 0o600)
	_ = os.WriteFile(keyPath, otherKeyPEM, 0o600)

	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{CA: caPath, Cert: certPath, Key: keyPath},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(cfg, log, &obs.State{}); err == nil {
		t.Fatal("expected error for a mismatched cert/key pair")
	}
}

func TestHandleIngressRoutesByHost(t *testing.T) {
	// Two "agents" behind yamux over net.Pipe, registered under two fingerprints.
	srvA, cliA := newServerSession(t)
	srvB, cliB := newServerSession(t)
	defer cliA.Close()
	defer cliB.Close()

	e := &Edge{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: &obs.State{},
		reg:   newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{
			{Pattern: "app.example.com", Value: &routeState{fingerprint: "FP-A"}},
			{Pattern: "api.example.com", Value: &routeState{fingerprint: "FP-B"}},
		}),
	}
	e.reg.set("FP-A", srvA)
	e.reg.set("FP-B", srvB)

	// Agent A echoes the preamble host; assert it is hit for app.example.com.
	go func() {
		st, err := cliA.AcceptStream()
		if err != nil {
			return
		}
		p, _ := tunnel.ReadPreamble(st)
		_, _ = st.Write([]byte("HOST=" + p.Host))
		_ = st.Close()
	}()

	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"))
	}()
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got := string(buf[:n]); got != "HOST=app.example.com" {
		t.Fatalf("echo = %q, want HOST=app.example.com", got)
	}
	_ = client.Close()

	// Unknown host -> 404.
	c2, edge2 := net.Pipe()
	go e.handleIngress(edge2)
	go func() { _, _ = c2.Write([]byte("GET / HTTP/1.1\r\nHost: nope.org\r\n\r\n")) }()
	resp := make([]byte, 64)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ = c2.Read(resp)
	if !strings.Contains(string(resp[:n]), "404") {
		t.Fatalf("expected 404, got %q", resp[:n])
	}
	_ = c2.Close()
}

func TestGlobalConnectionCap(t *testing.T) {
	e := &Edge{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: &obs.State{},
		reg:   newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{
			{Pattern: "*", Value: &routeState{fingerprint: "FP"}},
		}),
		sem: newSemaphore(1),
	}
	// Occupy the only global slot.
	if !e.sem.tryAcquire() {
		t.Fatal("setup acquire failed")
	}
	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "503") {
		t.Fatalf("expected 503, got %q", buf[:n])
	}
	_ = client.Close()
}

func TestPerRouteConnectionCap(t *testing.T) {
	srv, cli := newServerSession(t)
	defer cli.Close()
	rs := &routeState{fingerprint: "FP", sem: newSemaphore(1)}
	e := &Edge{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  &obs.State{},
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "*", Value: rs}}),
	}
	e.reg.set("FP", srv)
	// Occupy the route's only slot.
	if !rs.sem.tryAcquire() {
		t.Fatal("setup acquire failed")
	}
	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "503") {
		t.Fatalf("expected 503 from per-route cap, got %q", buf[:n])
	}
	_ = client.Close()
}
