package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// startBackend is a tiny TCP server that answers HTTP GET with a body and
// upgrades + echoes when it sees a WebSocket Upgrade request.
func startBackend(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveBackend(c)
		}
	}()
	return ln
}

func serveBackend(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(c, br) // echo post-upgrade bytes
		return
	}
	const body = "hello from backend"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// startStack wires backend + edge + agent and returns the ingress address.
// If ingressTLS is non-nil the ingress terminates TLS (standalone mode);
// otherwise it is plaintext (proxied mode).
func startStack(t *testing.T, ingressTLS *tls.Config) (ingressAddr string, edgeBuf, agentBuf *syncBuf) {
	t.Helper()
	backend := startBackend(t)

	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := writeFile(t, dir, "ca.crt", ca.CertPEM())
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCertPath := writeFile(t, dir, "edge.crt", ecPEM)
	edgeKeyPath := writeFile(t, dir, "edge.key", ekPEM)
	acPEM, akPEM, _ := ca.IssueClient("agent-1")
	agentCertPath := writeFile(t, dir, "agent.crt", acPEM)
	agentKeyPath := writeFile(t, dir, "agent.key", akPEM)

	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)

	edgeBuf, agentBuf = &syncBuf{}, &syncBuf{}
	edgeLog, _, _ := obs.NewLogger("debug", "text", edgeBuf)
	agentLog, _, _ := obs.NewLogger("debug", "text", agentBuf)
	var edgeState, agentState obs.State

	edgeCfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied"},
		Tunnel:  config.TunnelServerConfig{CA: caPath, Cert: edgeCertPath, Key: edgeKeyPath},
	}
	e, err := edge.New(edgeCfg, edgeLog, &edgeState)
	if err != nil {
		t.Fatal(err)
	}

	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	rawIngress, _ := net.Listen("tcp", "127.0.0.1:0")
	var ingressLn net.Listener = rawIngress
	if ingressTLS != nil {
		ingressLn = tls.NewListener(rawIngress, ingressTLS)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	agentCfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: tunLn.Addr().String(), CA: caPath, Cert: agentCertPath, Key: agentKeyPath},
		Service:   config.ServiceConfig{Address: backend.Addr().String()},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
	}
	a, err := agent.New(agentCfg, agentLog, &agentState)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for !edgeState.Snapshot().TunnelConnected {
		if time.Now().After(deadline) {
			t.Fatal("tunnel never connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ingressLn.Addr().String(), edgeBuf, agentBuf
}

func TestEndToEndHTTP(t *testing.T) {
	addr, _, _ := startStack(t, nil)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "hello from backend") {
		t.Fatalf("bad response: %q", resp)
	}
}

func TestEndToEndWebSocketAndCorrelation(t *testing.T) {
	addr, edgeBuf, agentBuf := startStack(t, nil)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("expected 101 upgrade, got %q", status)
	}
	for { // consume response headers up to the blank line
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_, _ = io.WriteString(conn, "PING-DATA")
	got := make([]byte, len("PING-DATA"))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "PING-DATA" {
		t.Fatalf("ws echo got %q", got)
	}

	// The same conn_id must appear in both edge and agent logs.
	re := regexp.MustCompile(`conn_id=([0-9a-f]+)`)
	m := re.FindStringSubmatch(edgeBuf.String())
	if m == nil {
		t.Fatalf("no conn_id in edge log:\n%s", edgeBuf.String())
	}
	connID := m[1]
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(agentBuf.String(), "conn_id="+connID) {
		if time.Now().After(deadline) {
			t.Fatalf("conn_id %s not found in agent log:\n%s", connID, agentBuf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEndToEndStandaloneTLS(t *testing.T) {
	ca, _ := pki.CreateCA()
	pubCertPEM, pubKeyPEM, _ := ca.IssueServer("localhost")
	pubCert, _ := tls.X509KeyPair(pubCertPEM, pubKeyPEM)
	ingressTLS := &tls.Config{Certificates: []tls.Certificate{pubCert}, MinVersion: tls.VersionTLS12}

	addr, _, _ := startStack(t, ingressTLS)
	client, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	resp, _ := io.ReadAll(client)
	if !strings.Contains(string(resp), "hello from backend") {
		t.Fatalf("standalone TLS response: %q", resp)
	}
}
