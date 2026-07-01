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
