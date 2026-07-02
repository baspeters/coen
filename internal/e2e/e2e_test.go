package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

// fingerprintOf derives the edge-side route fingerprint for an issued client cert.
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

// startStack wires a single backend under a catch-all route and returns the
// ingress address. If ingressTLS is non-nil the ingress terminates TLS
// (standalone mode); otherwise it is plaintext (proxied mode).
func startStack(t *testing.T, ingressTLS *tls.Config) (ingressAddr string, edgeBuf, agentBuf *syncBuf) {
	t.Helper()
	backend := startBackend(t)
	return buildStack(t, ingressTLS,
		[]string{"*"},
		[]config.AgentRoute{{Host: "*", Service: backend.Addr().String()}})
}

// buildStack wires edge + agent with the given edge host patterns (all owned by
// the single test agent) and agent host->backend routes, then waits for the
// tunnel to register. It returns the ingress address and the log buffers.
func buildStack(t *testing.T, ingressTLS *tls.Config, edgeHosts []string, agentRoutes []config.AgentRoute) (ingressAddr string, edgeBuf, agentBuf *syncBuf) {
	t.Helper()
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
	agentFP := fingerprintOf(t, acPEM)

	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)

	edgeBuf, agentBuf = &syncBuf{}, &syncBuf{}
	edgeLog, _, _ := obs.NewLogger("debug", "text", edgeBuf)
	agentLog, _, _ := obs.NewLogger("debug", "text", agentBuf)
	var edgeState, agentState obs.State

	edgeRoutes := make([]config.EdgeRoute, len(edgeHosts))
	for i, h := range edgeHosts {
		edgeRoutes[i] = config.EdgeRoute{Host: h, AgentFingerprint: agentFP}
	}
	edgeCfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied"},
		Tunnel:  config.TunnelServerConfig{CA: caPath, Cert: edgeCertPath, Key: edgeKeyPath},
		Routes:  edgeRoutes,
	}
	e, err := edge.New(edgeCfg, edgeLog, &edgeState)
	if err != nil {
		t.Fatal(err)
	}

	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	rawIngress, _ := net.Listen("tcp", "127.0.0.1:0")
	ingressLn := rawIngress
	if ingressTLS != nil {
		ingressLn = tls.NewListener(rawIngress, ingressTLS)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()

	agentCfg := &config.AgentConfig{
		Edge:      config.EdgeRef{Address: tunLn.Addr().String(), CA: caPath, Cert: agentCertPath, Key: agentKeyPath},
		Routes:    agentRoutes,
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
	}
	a, err := agent.New(agentCfg, agentLog, &agentState)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for len(edgeState.Snapshot().Agents) == 0 {
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

// startBackendBody is a minimal HTTP backend that answers every request with a
// fixed body, used to distinguish which backend a host routed to.
func startBackendBody(t *testing.T, body string) net.Listener {
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
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	return ln
}

func TestEndToEndHostRouting(t *testing.T) {
	appBackend := startBackendBody(t, "backend-app")
	apiBackend := startBackendBody(t, "backend-api")

	addr, _, _ := buildStack(t, nil,
		[]string{"app.example.com", "api.example.com"},
		[]config.AgentRoute{
			{Host: "app.example.com", Service: appBackend.Addr().String()},
			{Host: "api.example.com", Service: apiBackend.Addr().String()},
		})

	get := func(host string) string {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		resp, _ := io.ReadAll(conn)
		return string(resp)
	}

	if got := get("app.example.com"); !strings.Contains(got, "backend-app") {
		t.Fatalf("app.example.com routed wrong: %q", got)
	}
	if got := get("api.example.com"); !strings.Contains(got, "backend-api") {
		t.Fatalf("api.example.com routed wrong: %q", got)
	}
	// A host with no route gets a 404 from the edge.
	if got := get("unknown.example.com"); !strings.Contains(got, "404") {
		t.Fatalf("unknown host should 404, got: %q", got)
	}
}
