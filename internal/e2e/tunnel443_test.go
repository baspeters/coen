package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/netx/proxytest"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

// sharedStack is a standalone edge that takes agents on its ingress port
// (tunnel.share_ingress) and has no tunnel listener of its own.
type sharedStack struct {
	addr        string // the ingress, for clients and agents alike
	publicRoots *x509.CertPool
	caPath      string
	agentCert   string
	agentKey    string
	agentPEM    tls.Certificate
	coenRoots   *x509.CertPool
	backend     string
	edge        *obs.State
	ctx         context.Context
}

// freeAddr returns a loopback address with a port nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func buildSharedStack(t *testing.T, maxConns int, readHeader time.Duration) *sharedStack {
	t.Helper()
	// Requests while no agent is connected (the cap test's probes) answer
	// at once.
	return buildSharedStackWait(t, maxConns, readHeader, config.NewDuration(0))
}

// buildSharedStackWait is buildSharedStack with agent_wait set (nil: the
// default).
func buildSharedStackWait(t *testing.T, maxConns int, readHeader time.Duration, agentWait *config.Duration) *sharedStack {
	t.Helper()
	dir := t.TempDir()
	ca, _ := pki.CreateCA()
	caPath := writeFile(t, dir, "ca.crt", ca.CertPEM())
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	acPEM, akPEM, _ := ca.IssueClient("agent")
	// The public certificate comes from another CA, as in production, so a
	// client that ends up with the wrong one notices.
	public, _ := pki.CreateCA()
	pcPEM, pkPEM, _ := public.IssueServer("127.0.0.1")
	publicRoots, _ := pki.CertPoolFromPEM(public.CertPEM())
	coenRoots, _ := pki.CertPoolFromPEM(ca.CertPEM())
	agentPair, _ := tls.X509KeyPair(acPEM, akPEM)
	st := &sharedStack{
		addr:        freeAddr(t),
		publicRoots: publicRoots,
		caPath:      caPath,
		agentCert:   writeFile(t, dir, "agent.crt", acPEM),
		agentKey:    writeFile(t, dir, "agent.key", akPEM),
		agentPEM:    agentPair,
		coenRoots:   coenRoots,
		backend:     echoBackend(t, 0),
		edge:        obs.NewState("edge"),
	}
	log, _, _ := obs.NewLogger("error", "text", io.Discard)
	e, err := edge.New(&config.EdgeConfig{
		Ingress: config.IngressConfig{
			Mode:              "standalone",
			Listen:            st.addr,
			MaxConnections:    maxConns,
			ReadHeaderTimeout: config.Duration(readHeader),
			TLS:               config.TLSFiles{Cert: writeFile(t, dir, "public.crt", pcPEM), Key: writeFile(t, dir, "public.key", pkPEM)},
		},
		Tunnel:    config.TunnelServerConfig{ShareIngress: true, CA: caPath, Cert: writeFile(t, dir, "edge.crt", ecPEM), Key: writeFile(t, dir, "edge.key", ekPEM)},
		Routes:    []config.EdgeRoute{{Host: "*", AgentFingerprint: fingerprintOf(t, acPEM)}},
		Drain:     config.Duration(time.Second),
		AgentWait: agentWait,
	}, log, st.edge)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	st.ctx = ctx
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("edge: %v", err)
		}
	})
	for end := time.Now().Add(5 * time.Second); ; {
		c, err := net.Dial("tcp", st.addr)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(end) {
			t.Fatalf("the edge did not listen on %s: %v", st.addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return st
}

// startAgent runs an agent that dials the shared ingress, through proxy when
// set, until the test ends.
func (s *sharedStack) startAgent(t *testing.T, proxy string) *obs.State {
	t.Helper()
	state := obs.NewState("agent")
	log, _, _ := obs.NewLogger("error", "text", io.Discard)
	ag, err := agent.New(&config.AgentConfig{
		Edge:      config.EdgeRef{Address: s.addr, CA: s.caPath, Cert: s.agentCert, Key: s.agentKey, Proxy: proxy},
		Routes:    []config.AgentRoute{{Host: "*", Service: s.backend}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
		Drain:     config.Duration(time.Second),
	}, log, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	done := make(chan struct{})
	go func() { _ = ag.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return state
}

// client is an HTTPS client of the ingress that trusts the public CA.
func (s *sharedStack) client() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.publicRoots, ServerName: "127.0.0.1"}}}
}

func (s *sharedStack) get(t *testing.T, path string) string {
	t.Helper()
	resp, err := s.client().Get("https://" + s.addr + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}

// One port, two kinds of client: the agent tunnel and HTTPS both work on it.
func TestSharedIngressCarriesAgentsAndClients(t *testing.T) {
	st := buildSharedStack(t, 0, 0)
	ag := st.startAgent(t, "")
	waitSessions(t, st.edge, 1)
	if body := st.get(t, "/shared?x=1"); !strings.HasPrefix(body, "GET /shared?x=1 ") {
		t.Fatalf("backend saw %q", body)
	}
	// Browsers offer h2 and http/1.1; they get the public certificate.
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: st.publicRoots, ServerName: "127.0.0.1", NextProtos: []string{"h2", "http/1.1"}}}}
	resp, err := c.Get("https://" + st.addr + "/browser")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 1 {
		t.Fatalf("browser-like client: %d over %s", resp.StatusCode, resp.Proto)
	}
	snap := st.edge.Snapshot()
	if snap.HandshakeOK != 1 || snap.HandshakeRejected != 0 {
		t.Fatalf("tunnel handshakes: %d ok, %d rejected", snap.HandshakeOK, snap.HandshakeRejected)
	}
	if !ag.Snapshot().TunnelConnected {
		t.Fatal("the agent is not connected")
	}
}

// A client that asks for the tunnel but cannot authenticate is a rejected
// tunnel handshake, not a bad ingress request; one that offers no ALPN (an
// agent older than the tunnel ALPN) gets the public certificate and fails
// to verify it.
func TestSharedIngressTunnelHandshakes(t *testing.T) {
	st := buildSharedStack(t, 0, 0)
	dial := func(cfg *tls.Config) error {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", st.addr, cfg)
		if err == nil {
			// TLS 1.3 reports a refused client certificate on the first read.
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = c.Read(make([]byte, 1))
			_ = c.Close()
		}
		return err
	}
	if err := dial(&tls.Config{RootCAs: st.coenRoots, ServerName: "127.0.0.1", NextProtos: []string{tunnel.ALPNv2}, MinVersion: tls.VersionTLS13}); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("no client certificate: %v", err)
	}
	for end := time.Now().Add(2 * time.Second); st.edge.Snapshot().HandshakeRejected != 1; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("rejected: %d, want 1", st.edge.Snapshot().HandshakeRejected)
		}
	}
	old := tunnel.ClientTLSConfig(st.coenRoots, st.agentPEM, "127.0.0.1")
	old.NextProtos = nil // as an agent from before v0.4.0
	if err := dial(old); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("an agent without the tunnel ALPN: %v", err)
	}
	// Only the old agent counts as a bad ingress request: its handshake failed
	// on the public side. The edge counts it once the client has gone.
	for end := time.Now().Add(2 * time.Second); st.edge.Detail().UnroutedFailures.Get(obs.ReasonBadRequest) != 1; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("bad_request: %d, want 1", st.edge.Detail().UnroutedFailures.Get(obs.ReasonBadRequest))
		}
	}
	if got := st.edge.Snapshot().HandshakeRejected; got != 1 {
		t.Fatalf("rejected: %d, want 1", got)
	}
}

// An agent arriving while the ingress is at its cap still connects, and its
// session holds no ingress slot afterwards.
func TestSharedIngressAgentAtTheCap(t *testing.T) {
	st := buildSharedStack(t, 1, 3*time.Second)
	status := func() int {
		resp, err := st.client().Get("https://" + st.addr + "/probe")
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Hold the only slot with a client that connects and sends nothing, and
	// wait until it provably holds it (another request gets 503).
	var hold net.Conn
	for end := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if hold == nil {
			c, err := tls.Dial("tcp", st.addr, &tls.Config{RootCAs: st.publicRoots, ServerName: "127.0.0.1"})
			if err == nil {
				hold = c
			}
		}
		if hold != nil && status() == 503 {
			break
		}
		if hold != nil {
			_ = hold.Close() // it may have been the one refused: try again
			hold = nil
		}
		if time.Now().After(end) {
			t.Fatal("could not fill the ingress cap")
		}
	}
	refused := st.edge.Detail().UnroutedFailures.Get(obs.ReasonMaxConnections)
	st.startAgent(t, "")
	waitSessions(t, st.edge, 1)
	if got := st.edge.Detail().UnroutedFailures.Get(obs.ReasonMaxConnections); got != refused {
		t.Fatalf("the agent was counted as a refused connection (%d -> %d)", refused, got)
	}
	_ = hold.Close()
	// With the agent connected, the one slot serves clients again.
	for end := time.Now().Add(3 * time.Second); status() != 200; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the slot did not come back")
		}
	}
}

// An agent behind an HTTP proxy reaches the shared port with CONNECT, as
// one in a network that allows only CONNECT to port 443 would.
func TestAgentThroughConnectProxy(t *testing.T) {
	st := buildSharedStack(t, 0, 0)
	_, port, _ := net.SplitHostPort(st.addr)
	p := proxytest.Start(t, proxytest.Options{User: "agent", Password: "pw", AllowPorts: []string{port}})
	st.startAgent(t, p.URL.String())
	waitSessions(t, st.edge, 1)
	if body := st.get(t, "/via-proxy"); !strings.HasPrefix(body, "GET /via-proxy ") {
		t.Fatalf("backend saw %q", body)
	}
	if tg := p.Targets(); len(tg) == 0 || tg[0] != st.addr {
		t.Fatalf("the proxy saw %v", tg)
	}

	// Wrong credentials: the agent keeps retrying and never connects.
	bad := *p.URL
	bad.User = url.UserPassword("agent", "nope")
	ag := st.startAgent(t, bad.String())
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ag.Snapshot().TunnelConnected {
			t.Fatal("connected with wrong proxy credentials")
		}
	}
	if s := ag.Snapshot(); s.HandshakeFail == 0 || !strings.Contains(s.LastError, "407") {
		t.Fatalf("failures %d, last error %q", s.HandshakeFail, s.LastError)
	}
}

// Sharing the port must not give a slow client more time: the TLS handshake
// and the request head together still have read_header_timeout.
func TestSharedIngressKeepsOneHeaderDeadline(t *testing.T) {
	st := buildSharedStack(t, 0, time.Second)
	raw, err := net.Dial("tcp", st.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	time.Sleep(700 * time.Millisecond)
	c := tls.Client(raw, &tls.Config{RootCAs: st.publicRoots, ServerName: "127.0.0.1"})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond) // 1.4s in: past the deadline
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	if strings.HasPrefix(string(b), "HTTP/1.1") {
		t.Fatalf("a request head finished 1.4s after connecting was served (1s limit): %q", b[:min(len(b), 40)])
	}
	if got := st.edge.Detail().HeaderTimeouts; got != 1 {
		t.Fatalf("header timeouts: %d, want 1", got)
	}
}
