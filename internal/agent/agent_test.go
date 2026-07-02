package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
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
		Service:   config.ServiceConfig{Address: svcLn.Addr().String()},
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
		Service:   config.ServiceConfig{Address: "127.0.0.1:1"},
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
		Service:   config.ServiceConfig{Address: "127.0.0.1:1"}, // never dialed (no streams)
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
