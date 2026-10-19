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
	"github.com/hashicorp/yamux"
)

// Against an older edge (no drain support negotiated) the agent keeps the old
// shutdown and does not wait for a drain acknowledgement. (That it sends no
// GoAway is checked against a real older edge in the smoke tests.)
func TestShutdownAgainstOlderEdge(t *testing.T) {
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
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())

	oldTLS := tunnel.ServerTLSConfig(pool, edgeCert)
	oldTLS.NextProtos = nil // an edge from before the drain handshake
	tcpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	edgeLn := tls.NewListener(tcpLn, oldTLS)
	defer edgeLn.Close()

	sessUp := make(chan *yamux.Session, 1)
	go func() {
		conn, err := edgeLn.Accept()
		if err != nil {
			return
		}
		sess, err := tunnel.ServerSession(conn)
		if err != nil {
			return
		}
		sessUp <- sess
		<-sess.CloseChan()
	}()

	a, err := New(&config.AgentConfig{
		Edge:      config.EdgeRef{Address: edgeLn.Addr().String(), CA: caPath, Cert: certPath, Key: keyPath},
		Routes:    []config.AgentRoute{{Host: "*", Service: "127.0.0.1:1"}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(50 * time.Millisecond)},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), obs.NewState("agent"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	select {
	case <-sessUp:
	case <-time.After(3 * time.Second):
		t.Fatal("agent never connected")
	}
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("shutdown against an older edge took %v; it must not wait for a drain acknowledgement", d)
	}
}
