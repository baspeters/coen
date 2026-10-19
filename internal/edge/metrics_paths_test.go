package edge

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/route"
)

func testEdge(st *obs.State, rs *routeState) *Edge {
	return &Edge{
		cfg:    &config.EdgeConfig{Ingress: config.IngressConfig{ReadHeaderTimeout: config.Duration(200 * time.Millisecond)}},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "*", Value: rs}}),
	}
}

// A plain TCP connection that closes without sending a byte (health check,
// port scan) is not a malformed request: no 400, no bad_request count.
func TestHandleIngressEmptyConnectionNotCounted(t *testing.T) {
	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP", stats: st.Route("*")})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			e.handleIngress(c)
		}
		close(done)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleIngress did not return for an empty connection")
	}
	if n := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); n != 0 {
		t.Fatalf("empty connection counted as bad_request (%d)", n)
	}
}

// A client that connects and never sends a byte is cut off at the read-header
// deadline (slow-loris protection) but is not a malformed request: no 400 and
// no bad_request. A partial head that stalls is (see TestReadHeaderTimeout).
func TestHandleIngressIdleClientIsCutOffQuietly(t *testing.T) {
	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			e.handleIngress(c)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, _ := io.ReadAll(c)
	if len(resp) != 0 {
		t.Fatalf("idle client should be closed without a response, got %q", resp)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("idle client was not cut off at the deadline (took %v)", d)
	}
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 0 {
		t.Fatalf("idle client counted as bad_request (%d)", got)
	}
	if got := st.Detail().HeaderTimeouts; got != 1 {
		t.Fatalf("header timeouts = %d, want 1", got)
	}
}

// When the stream preamble cannot be written, the client gets a 502 instead of
// a silently closed connection, and stream_error is counted on the route.
func TestHandleIngressPreambleFailureReturns502(t *testing.T) {
	srv, cli := newServerSession(t)
	defer cli.Close()
	st := obs.NewState("edge")
	rs := &routeState{fingerprint: "FP", stats: st.Route("*")}
	e := testEdge(st, rs)
	if !e.reg.register("FP", srv) {
		t.Fatal("register failed")
	}
	// A Host longer than the preamble limit makes WritePreamble fail.
	host := strings.Repeat("a", 5000) + ".example.com"
	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")) }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, _ := io.ReadAll(client)
	if !strings.Contains(string(resp), "502") {
		t.Fatalf("want a 502, got %q", resp)
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError); got != 1 {
		t.Fatalf("stream_error = %d, want 1", got)
	}
}

func TestReadRequestHeadNoRequest(t *testing.T) {
	if _, _, err := readRequestHead(strings.NewReader(""), 1<<16); !errors.Is(err, errNoRequest) {
		t.Fatalf("empty EOF: got %v, want errNoRequest", err)
	}
	if _, _, err := readRequestHead(errReader{err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}, 1<<16); !errors.Is(err, errNoRequest) {
		t.Fatalf("reset before any byte: got %v, want errNoRequest", err)
	}
	if _, _, err := readRequestHead(errReader{err: errTest}, 1<<16); err == nil || errors.Is(err, errNoRequest) {
		t.Fatalf("a read error before any byte must stay a bad request, got %v", err)
	}
	if _, _, err := readRequestHead(strings.NewReader("GET"), 1<<16); err == nil || errors.Is(err, errNoRequest) {
		t.Fatalf("partial head must be a bad request, got %v", err)
	}
}

// On the standalone ingress the first read runs the TLS handshake. A client
// that rejects the public certificate sent bytes (its ClientHello), so it is a
// bad request worth counting, not a silent early close.
func TestHandleIngressTLSHandshakeFailureIsBadRequest(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServer("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP"})
	client, edgeConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.handleIngress(tls.Server(edgeConn, &tls.Config{Certificates: []tls.Certificate{cert}}))
		close(done)
	}()
	// The client trusts no CA, so it rejects the edge certificate.
	tc := tls.Client(client, &tls.Config{ServerName: "app.example.com", RootCAs: x509.NewCertPool()})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake should fail for an untrusted certificate")
	}
	_ = tc.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleIngress did not return")
	}
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 1 {
		t.Fatalf("bad_request = %d, want 1 for a rejected certificate", got)
	}
}

// Route labels use the normalized host pattern, matching the agent's labels
// for the same route even when the configs differ in case or a trailing dot.
func TestRouteStatsUseNormalizedPattern(t *testing.T) {
	st := obs.NewState("edge")
	dir := t.TempDir()
	ca, _ := pki.CreateCA()
	certPEM, keyPEM, _ := ca.IssueServer("127.0.0.1")
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	for p, b := range map[string][]byte{caPath: ca.CertPEM(), certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.EdgeConfig{
		Tunnel: config.TunnelServerConfig{CA: caPath, Cert: certPath, Key: keyPath},
		Routes: []config.EdgeRoute{{Host: "App.Example.COM.", AgentFingerprint: "FP"}},
	}
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st); err != nil {
		t.Fatal(err)
	}
	if routes := st.Detail().Routes; len(routes) != 1 || routes[0].Pattern != "app.example.com" {
		t.Fatalf("route label = %+v, want app.example.com", routes)
	}
}

// hangUpOnRead closes the connection the first time the client tries to read,
// so a TLS client sends its ClientHello and then drops without any alert.
type hangUpOnRead struct{ net.Conn }

func (h hangUpOnRead) Read([]byte) (int, error) {
	_ = h.Close()
	return 0, io.EOF
}

// stallOnRead blocks the client's first read until released, so its ClientHello
// is sent and nothing follows.
type stallOnRead struct {
	net.Conn
	release chan struct{}
}

func (s stallOnRead) Read([]byte) (int, error) {
	<-s.release
	return 0, io.EOF
}

// resetOnRead resets the TCP connection the first time the client tries to
// read, so a TLS client sends its ClientHello and then aborts with an RST.
type resetOnRead struct{ *net.TCPConn }

func (r resetOnRead) Read([]byte) (int, error) {
	_ = r.SetLinger(0)
	_ = r.Close()
	return 0, io.EOF
}

// On a real standalone listener, an empty TCP connection is ignored while a TLS
// handshake abandoned after the ClientHello is still a counted bad request.
func TestStandaloneIngressEmptyVersusAbandonedHandshake(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := ca.IssueServer("app.example.com")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(wireListener{raw}, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()

	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP"})
	handled := make(chan struct{}, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { e.handleIngress(c); handled <- struct{}{} }()
		}
	}()
	wait := func() {
		select {
		case <-handled:
		case <-time.After(3 * time.Second):
			t.Fatal("handleIngress did not return")
		}
	}

	// 1. Connect and close: nothing on the wire.
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	wait()
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 0 {
		t.Fatalf("empty TCP connection counted as bad_request (%d)", got)
	}

	// 2. ClientHello, then hang up without an alert.
	c, err = net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = tls.Client(hangUpOnRead{c}, &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true}).Handshake()
	wait()
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 1 {
		t.Fatalf("abandoned TLS handshake: bad_request = %d, want 1", got)
	}

	// 3. Browser preconnect: complete the handshake, then close unused, once
	// cleanly and once with a TCP reset (SO_LINGER 0), as real clients do.
	for _, reset := range []bool{false, true} {
		rc, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tc := tls.Client(rc, &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		if reset {
			_ = rc.(*net.TCPConn).SetLinger(0)
			_ = rc.Close()
		} else {
			_ = tc.Close()
		}
		wait()
		if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 1 {
			t.Fatalf("preconnect (reset=%v) counted as bad_request (total %d, want 1)", reset, got)
		}
	}

	// 3b. Preconnect that completes TLS and then idles past the deadline.
	idle, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	wait() // the edge's 200ms read-header deadline fires
	_ = idle.Close()
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 1 {
		t.Fatalf("idle preconnect counted as bad_request (total %d, want 1)", got)
	}

	// 4. ClientHello, then a reset: an abandoned handshake, still counted.
	rc, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = tls.Client(resetOnRead{rc.(*net.TCPConn)}, &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true}).Handshake()
	wait()
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 2 {
		t.Fatalf("handshake abandoned with a reset: bad_request = %d, want 2", got)
	}

	// 5. ClientHello, then silence until the deadline: a stalled handshake.
	sc, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	stall := make(chan struct{})
	go func() {
		_ = tls.Client(stallOnRead{sc, stall}, &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true}).Handshake()
	}()
	wait()
	close(stall)
	_ = sc.Close()
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest); got != 3 {
		t.Fatalf("stalled handshake: bad_request = %d, want 3", got)
	}
}

func TestClosedWithoutRequestClassification(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if closedWithoutRequest(a) {
		t.Fatal("an unrecognised connection type must not be treated as benign")
	}
	if closedWithoutRequest(tls.Server(a, &tls.Config{})) {
		t.Fatal("a TLS connection without a wireConn underneath must not be treated as benign")
	}
}

// A preamble write that fails because the session shut down evicts it, like an
// OpenStream failure; a failure on a live session (oversized preamble) keeps it.
func TestPreambleFailureEvictsOnlyDeadSession(t *testing.T) {
	srv, cli := newServerSession(t)
	defer cli.Close()
	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP", stats: st.Route("*")})
	if !e.reg.register("FP", srv) {
		t.Fatal("register failed")
	}
	host := strings.Repeat("a", 5000) + ".example.com"
	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")) }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(client)
	if _, ok := e.reg.get("FP"); !ok {
		t.Fatal("a live session must not be evicted for an oversized preamble")
	}
	// Shut the session down so the next write fails because the tunnel is gone.
	_ = srv.Close()
	_ = cli.Close()
	e.evict("FP", srv)
	if _, ok := e.reg.get("FP"); ok {
		t.Fatal("evict must remove the dead session")
	}
}

// A peer that sends a ClientHello to the tunnel port and then resets is a
// rejected handshake (scanner or misconfigured agent), as before: only a clean
// close or a closed listener is benign there.
func TestTunnelHandshakeResetIsRejected(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	_ = ingressLn.Close()
	go func() {
		c, err := tunLn.Accept()
		if err == nil {
			e.serveAgent(c)
		}
	}()
	rc, err := net.Dial("tcp", tunLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = tls.Client(resetOnRead{rc.(*net.TCPConn)}, &tls.Config{InsecureSkipVerify: true}).Handshake()
	deadline := time.Now().Add(3 * time.Second)
	for e.state.Snapshot().HandshakeRejected != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("rejected = %d, want 1 for a reset after the ClientHello", e.state.Snapshot().HandshakeRejected)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With the global cap full, a TLS client that sends nothing must not pin the
// handler: the 503 write (which first runs the handshake) is bounded by the
// read-header deadline.
func TestMaxConnectionsRejectionIsBoundedOnTLS(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := ca.IssueServer("app.example.com")
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	st := obs.NewState("edge")
	e := testEdge(st, &routeState{fingerprint: "FP"})
	e.sem = newSemaphore(1)
	if !e.sem.tryAcquire() { // the cap is already full
		t.Fatal("acquire")
	}
	client, edgeConn := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		e.handleIngress(tls.Server(edgeConn, &tls.Config{Certificates: []tls.Certificate{cert}}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the 503 write on a silent TLS client was not bounded")
	}
	if got := st.Detail().UnroutedFailures.Get(obs.ReasonMaxConnections); got != 1 {
		t.Fatalf("max_connections = %d, want 1", got)
	}
}
