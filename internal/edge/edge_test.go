package edge

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"github.com/baspeters/coen/internal/tunnel"
)

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

	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0", CA: caPath, Cert: certPath, Key: keyPath},
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
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
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
	for e.session.Load() == nil {
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
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "200 OK") {
		t.Fatalf("expected 200, got %q", resp)
	}
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
	for e.session.Load() == nil {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("agent never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	deadline = time.Now().Add(2 * time.Second)
	for e.state.Snapshot().TunnelConnected {
		if time.Now().After(deadline) {
			t.Fatal("edge did not tear down the agent session / clear state on shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
