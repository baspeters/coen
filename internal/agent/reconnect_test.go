package agent

import (
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

// newAgentAgainstEdge builds an agent whose edge is a TLS listener; serve
// handles each accepted connection (establish a session, keep it for some
// lifetime, then close).
func newAgentAgainstEdge(t *testing.T, minBackoff time.Duration, serve func(net.Conn)) *Agent {
	t.Helper()
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
	t.Cleanup(func() { _ = edgeLn.Close() })
	go func() {
		for {
			conn, err := edgeLn.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()

	cfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(minBackoff), MaxBackoff: config.Duration(minBackoff * 4)},
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &obs.State{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestConnectOnceUnstableWhenEdgeDropsImmediately(t *testing.T) {
	// Edge accepts the mTLS handshake and establishes the session, then drops it
	// well under min_backoff (as it does after rejecting an unauthorized or
	// duplicate fingerprint). The brief hold lets the agent get past the
	// handshake into its accept loop, so this exercises the session-lifetime
	// path; it must still NOT reset the backoff.
	a := newAgentAgainstEdge(t, 500*time.Millisecond, func(conn net.Conn) {
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond) // past the handshake, under min_backoff
		_ = sess.Close()
		_ = conn.Close()
	})
	stable, err := a.connectOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error when the edge drops the session")
	}
	if stable {
		t.Fatal("connectOnce: stable = true; an immediately-dropped session must not reset backoff")
	}
}

func TestConnectOnceStableWhenSessionLivesLongEnough(t *testing.T) {
	const minBackoff = 10 * time.Millisecond
	a := newAgentAgainstEdge(t, minBackoff, func(conn net.Conn) {
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * minBackoff) // keep the session up well past min_backoff
		_ = sess.Close()
		_ = conn.Close()
	})
	stable, err := a.connectOnce(context.Background())
	if err == nil {
		t.Fatal("expected an error once the session closes")
	}
	if !stable {
		t.Fatal("connectOnce: stable = false; a long-lived session should reset backoff")
	}
}
