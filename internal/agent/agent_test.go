package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
)

func TestAgentBridgesStreamToService(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, acPEM, 0o600)
	_ = os.WriteFile(keyPath, akPEM, 0o600)

	edgeCertPEM, edgeKeyPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())

	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	edgeLn := tls.NewListener(tcpLn, tunnel.ServerTLSConfig(pool, edgeCert))
	defer edgeLn.Close()

	// Backend echo service.
	svcLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer svcLn.Close()
	go func() {
		c, err := svcLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	got := make(chan string, 1)
	go func() {
		conn, err := edgeLn.Accept()
		if err != nil {
			return
		}
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			return
		}
		stream, err := sess.OpenStream()
		if err != nil {
			return
		}
		_ = tunnel.WritePreamble(stream, tunnel.Preamble{ConnID: "test1", ClientAddr: "203.0.113.1:1234"})
		_, _ = stream.Write([]byte("ping\n"))
		line, _ := bufio.NewReader(stream).ReadString('\n')
		got <- line
	}()

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: svcLn.Addr().String()}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(50 * time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, log, &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	select {
	case line := <-got:
		if line != "ping\n" {
			t.Fatalf("echo through agent got %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for echo through agent")
	}
}

func TestAgentRefusesMismatchedEdgeFingerprint(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, acPEM, 0o600)
	_ = os.WriteFile(keyPath, akPEM, 0o600)

	edgeCertPEM, edgeKeyPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())

	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	edgeLn := tls.NewListener(tcpLn, tunnel.ServerTLSConfig(pool, edgeCert))
	defer edgeLn.Close()

	// Fake edge: accept and complete the TLS handshake + yamux session on
	// every connection, then idle. The agent is expected to reject the
	// peer itself (fingerprint pin mismatch) before ever using the session.
	go func() {
		for {
			conn, err := edgeLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sess, err := tunnel.ServerSession(c)
				if err != nil {
					return
				}
				<-sess.CloseChan()
			}(conn)
		}
	}()

	cfg := &config.AgentConfig{
		Edge: config.EdgeRef{
			Address:         edgeLn.Addr().String(),
			CA:              caPath,
			Cert:            certPath,
			Key:             keyPath,
			EdgeFingerprint: "SHA256:nope",
		},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(5 * time.Millisecond), MaxBackoff: config.Duration(20 * time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	// Give the agent several reconnect attempts against the fingerprint-mismatched
	// edge; it must never report connected, and handshake failures must accumulate.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := state.Snapshot()
		if snap.TunnelConnected {
			t.Fatal("agent reported connected despite edge fingerprint mismatch")
		}
		if snap.HandshakeFail >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	snap := state.Snapshot()
	if snap.TunnelConnected {
		t.Fatal("agent reported connected despite edge fingerprint mismatch")
	}
	if snap.HandshakeFail < 1 {
		t.Fatalf("expected at least one handshake failure, got %d", snap.HandshakeFail)
	}
}

func TestAgentRunReturnsOnCtxCancelWhileConnected(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, acPEM, 0o600)
	_ = os.WriteFile(keyPath, akPEM, 0o600)
	edgeCertPEM, edgeKeyPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())

	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	edgeLn := tls.NewListener(tcpLn, tunnel.ServerTLSConfig(pool, edgeCert))
	defer edgeLn.Close()

	// Fake edge: accept, establish a yamux session, then stay idle (open no streams)
	// until the session closes (which happens when the agent shuts down).
	go func() {
		conn, err := edgeLn.Accept()
		if err != nil {
			return
		}
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			return
		}
		defer sess.Close()
		<-sess.CloseChan()
	}()

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}}, // never dialed (no streams)
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(50 * time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for !state.Snapshot().TunnelConnected {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("agent never connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after ctx cancel while connected/idle")
	}
}

// writeCAFile creates a fresh CA and writes its certificate to a temp file, for tests that
// only need a valid trust anchor on disk.
func writeCAFile(t *testing.T) (*pki.CA, string) {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(path, ca.CertPEM(), 0o600)
	return ca, path
}

// writeAgentPKI creates a fresh CA plus an agent client cert/key issued by it and writes all
// three to temp files, the trust material New() needs in order to succeed.
func writeAgentPKI(t *testing.T) (ca *pki.CA, caPath, certPath, keyPath string) {
	t.Helper()
	ca, caPath = writeCAFile(t)
	dir := filepath.Dir(caPath)
	certPath = filepath.Join(dir, "agent.crt")
	keyPath = filepath.Join(dir, "agent.key")
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, acPEM, 0o600)
	_ = os.WriteFile(keyPath, akPEM, 0o600)
	return ca, caPath, certPath, keyPath
}

// newEdgeListener starts a TLS listener presenting edgeCert and trusting clientCAPool for
// client certificates, mirroring the edge's mutual-TLS tunnel endpoint.
func newEdgeListener(t *testing.T, clientCAPool *x509.CertPool, edgeCert tls.Certificate) net.Listener {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(tcpLn, tunnel.ServerTLSConfig(clientCAPool, edgeCert))
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// openStreamAndWrite accepts a single connection on ln, establishes the yamux server
// session, opens one stream, invokes write on it, then blocks reading from it. The returned
// channel closes once that read unblocks, i.e. once the agent has closed its end of the
// stream, which happens as soon as handleStream returns (on a failed preamble read or a
// failed service dial).
func openStreamAndWrite(t *testing.T, ln net.Listener, write func(net.Conn) error) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			return
		}
		stream, err := sess.OpenStream()
		if err != nil {
			return
		}
		if err := write(stream); err != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = stream.Read(buf)
	}()
	return done
}

func TestNewMissingCAFile(t *testing.T) {
	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: "127.0.0.1:9999", CA: filepath.Join(t.TempDir(), "missing-ca.crt"), Cert: "unused-cert", Key: "unused-key"},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := New(cfg, log, &obs.State{})
	if err == nil || !strings.Contains(err.Error(), "read ca") {
		t.Fatalf("New() with missing CA file: got err %v, want error containing %q", err, "read ca")
	}
}

func TestNewInvalidCAPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caPath, []byte("not a pem certificate"), 0o600)

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: "127.0.0.1:9999", CA: caPath, Cert: "unused-cert", Key: "unused-key"},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(cfg, log, &obs.State{}); err == nil {
		t.Fatal("New() with invalid CA PEM: want error, got nil")
	}
}

func TestNewBadCertKeyPair(t *testing.T) {
	_, caPath := writeCAFile(t)
	dir := filepath.Dir(caPath)
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(certPath, []byte("not a certificate"), 0o600)
	_ = os.WriteFile(keyPath, []byte("not a key"), 0o600)

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: "127.0.0.1:9999", CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := New(cfg, log, &obs.State{})
	if err == nil || !strings.Contains(err.Error(), "load client cert") {
		t.Fatalf("New() with bad cert/key pair: got err %v, want error containing %q", err, "load client cert")
	}
}

func TestNewEdgeAddressMissingPort(t *testing.T) {
	_, caPath, certPath, keyPath := writeAgentPKI(t)

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: "no-port-host", CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := New(cfg, log, &obs.State{})
	if err == nil || !strings.Contains(err.Error(), `edge.address "no-port-host"`) {
		t.Fatalf("New() with portless edge address: got err %v, want error containing edge.address", err)
	}
}

func TestConnectOnceDialFailure(t *testing.T) {
	_, caPath, certPath, keyPath := writeAgentPKI(t)

	// Reserve then release a port so nothing is listening there.
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := reserve.Addr().String()
	_ = reserve.Close()

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: unreachable, CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	established, err := a.connectOnce(context.Background())
	if established {
		t.Fatal("connectOnce: established = true, want false on dial failure")
	}
	if err == nil || !strings.Contains(err.Error(), "dial edge") {
		t.Fatalf("connectOnce: got err %v, want error containing %q", err, "dial edge")
	}
	if got := state.Snapshot().HandshakeFail; got != 1 {
		t.Fatalf("HandshakeFail = %d, want 1", got)
	}
}

func TestConnectOnceTLSHandshakeFailureWrongCA(t *testing.T) {
	trustedCA, caPath, certPath, keyPath := writeAgentPKI(t)
	otherCA, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}

	// The edge presents a server cert signed by otherCA, which the agent does not trust
	// (the agent's tlsCfg only trusts trustedCA, loaded from caPath below).
	edgeCertPEM, edgeKeyPEM, _ := otherCA.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	// The edge trusts the agent's real client cert, so the client-cert side of the mutual
	// handshake is not what fails here; only server-cert verification is.
	edgeClientPool, _ := pki.CertPoolFromPEM(trustedCA.CertPEM())
	edgeLn := newEdgeListener(t, edgeClientPool, edgeCert)

	go func() {
		conn, err := edgeLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if tconn, ok := conn.(*tls.Conn); ok {
			_ = tconn.Handshake()
		}
	}()

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	established, err := a.connectOnce(ctx)
	if established {
		t.Fatal("connectOnce: established = true, want false on TLS handshake failure")
	}
	if err == nil || !strings.Contains(err.Error(), "tls handshake") {
		t.Fatalf("connectOnce: got err %v, want error containing %q", err, "tls handshake")
	}
	if got := state.Snapshot().HandshakeFail; got != 1 {
		t.Fatalf("HandshakeFail = %d, want 1", got)
	}
}

func TestHandleStreamServiceDialFailure(t *testing.T) {
	ca, caPath, certPath, keyPath := writeAgentPKI(t)
	edgeCertPEM, edgeKeyPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeLn := newEdgeListener(t, pool, edgeCert)

	// Reserve then release a port so the service dial fails deterministically.
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := reserve.Addr().String()
	_ = reserve.Close()

	streamClosed := openStreamAndWrite(t, edgeLn, func(stream net.Conn) error {
		return tunnel.WritePreamble(stream, tunnel.Preamble{ConnID: "dialfail", ClientAddr: "203.0.113.1:1234"})
	})

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: closedAddr}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(50 * time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	select {
	case <-streamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for agent to close the stream after a failed service dial")
	}

	snap := state.Snapshot()
	if snap.TotalStreams != 0 {
		t.Fatalf("TotalStreams = %d, want 0 (service dial should fail before StreamOpened)", snap.TotalStreams)
	}
	if snap.ActiveStreams != 0 {
		t.Fatalf("ActiveStreams = %d, want 0", snap.ActiveStreams)
	}
}

func TestHandleStreamMalformedPreamble(t *testing.T) {
	ca, caPath, certPath, keyPath := writeAgentPKI(t)
	edgeCertPEM, edgeKeyPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(edgeCertPEM, edgeKeyPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeLn := newEdgeListener(t, pool, edgeCert)

	svcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svcLn.Close()
	svcDialed := make(chan struct{}, 1)
	go func() {
		c, err := svcLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		svcDialed <- struct{}{}
	}()

	// A 2-byte length header claiming a body far larger than tunnel's maxPreamble (4096)
	// makes ReadPreamble fail immediately, without needing to send any body bytes.
	streamClosed := openStreamAndWrite(t, edgeLn, func(stream net.Conn) error {
		_, err := stream.Write([]byte{0xFF, 0xFF})
		return err
	})

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: svcLn.Addr().String()}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(50 * time.Millisecond)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := &obs.State{}
	a, err := New(cfg, log, state)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	select {
	case <-streamClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for agent to close the stream after a malformed preamble")
	}

	select {
	case <-svcDialed:
		t.Fatal("service was dialed despite a malformed preamble")
	default:
	}

	if got := state.Snapshot().TotalStreams; got != 0 {
		t.Fatalf("TotalStreams = %d, want 0 (preamble read should fail before StreamOpened)", got)
	}
}

func TestTLSVersion(t *testing.T) {
	cases := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS13, "1.3"},
		{tls.VersionTLS12, "1.2"},
	}
	for _, c := range cases {
		if got := tlsVersion(c.version); got != c.want {
			t.Errorf("tlsVersion(0x%04x) = %q, want %q", c.version, got, c.want)
		}
	}
	if got := tlsVersion(0x0301); !strings.Contains(got, "0x") {
		t.Errorf("tlsVersion(0x0301) = %q, want a string containing %q", got, "0x")
	}
}

func TestWithJitterZero(t *testing.T) {
	if got := withJitter(0); got != 0 {
		t.Fatalf("withJitter(0) = %v, want 0", got)
	}
}

func TestWithJitterRange(t *testing.T) {
	d := 100 * time.Millisecond
	lower, upper := d/2, d+d/2 // valid range is [d/2, 1.5d)
	for i := 0; i < 500; i++ {
		got := withJitter(d)
		if got < lower || got >= upper {
			t.Fatalf("withJitter(%v) = %v, want in [%v, %v)", d, got, lower, upper)
		}
	}
}

func TestHandleStreamRoutesToBackendByHost(t *testing.T) {
	// Backend that announces itself.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("BACKEND-OK"))
		_ = c.Close()
	}()

	a := &Agent{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: &obs.State{},
		routes: route.Build([]route.Entry[string]{
			{Pattern: "app.example.com", Value: ln.Addr().String()},
		}),
	}

	client, streamSide := net.Pipe()
	go a.handleStream(streamSide)
	if err := tunnel.WritePreamble(client, tunnel.Preamble{ConnID: "x", Host: "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "BACKEND-OK" {
		t.Fatalf("got %q, want BACKEND-OK", buf[:n])
	}
	_ = client.Close()
}

func TestHandleStreamNoRouteClosesStream(t *testing.T) {
	a := &Agent{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  &obs.State{},
		routes: route.Build([]route.Entry[string]{{Pattern: "app.example.com", Value: "127.0.0.1:1"}}),
	}
	client, streamSide := net.Pipe()
	go a.handleStream(streamSide)
	if err := tunnel.WritePreamble(client, tunnel.Preamble{ConnID: "x", Host: "unknown.example.com"}); err != nil {
		t.Fatal(err)
	}
	// With no matching route the agent closes the stream without dialing.
	buf := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected stream to be closed for an unrouted host")
	}
	_ = client.Close()
}

func TestAgentDrainStreams(t *testing.T) {
	a := &Agent{
		cfg:   &config.AgentConfig{Drain: config.Duration(2 * time.Second)},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: &obs.State{},
	}
	a.inflight.Add(1) // simulate one in-flight stream
	done := make(chan struct{})
	go func() { a.drainStreams(); close(done) }()
	select {
	case <-done:
		t.Fatal("drainStreams returned before in-flight finished")
	case <-time.After(50 * time.Millisecond):
	}
	a.inflight.Done()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainStreams did not return after in-flight finished")
	}
}

func TestAgentDrainStreamsTimeoutAndImmediate(t *testing.T) {
	a := &Agent{
		cfg: &config.AgentConfig{Drain: config.Duration(40 * time.Millisecond)},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.inflight.Add(1) // never Done: exercise the timeout branch
	done := make(chan struct{})
	go func() { a.drainStreams(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainStreams did not return after timeout")
	}
	a.inflight.Done()

	a0 := &Agent{cfg: &config.AgentConfig{Drain: 0}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a0.inflight.Add(1)
	a0.drainStreams() // drain_timeout 0: returns immediately
	a0.inflight.Done()
}
