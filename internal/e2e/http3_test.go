package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

// h3Stack is a standalone edge serving HTTP/3 and TLS over TCP, one agent,
// and an HTTP/1.1 backend that reports what it received.
type h3Stack struct {
	tcpAddr, udpAddr string
	roots            *x509.CertPool
	edge, agent      *obs.State
	udp              net.PacketConn
	stop             func() // shuts the edge down and waits for it
}

// echoBackend answers with what it received: method, target, selected
// headers, and the body's length and hash. /stream sends three flushed parts;
// /own-alt-svc sets its own Alt-Svc header.
func echoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/held": // headers at once, the first event after 1.5s
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(1500 * time.Millisecond)
			fmt.Fprint(w, "data: late\n\n")
			return
		case "/slow": // until the request goes away, or 5s
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		case "/ws": // a WebSocket upgrade, then a raw echo
			if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-Websocket-Key") == "" {
				http.Error(w, "not an upgrade", 400)
				return
			}
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			sum := sha1.Sum([]byte(r.Header.Get("Sec-Websocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
				base64.StdEncoding.EncodeToString(sum[:]), r.Header.Get("Sec-Websocket-Protocol"))
			_ = rw.Flush()
			// Echo frames; after echoing a Close frame (opcode 8), hang up, as
			// a WebSocket server does at the end of the closing handshake.
			buf := make([]byte, 4096)
			for {
				n, err := rw.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil || buf[0]&0x0f == 0x8 {
						return
					}
				}
				if err != nil {
					return
				}
			}
		case "/ws-deny":
			http.Error(w, "no websockets here", http.StatusForbidden)
			return
		case "/trailers":
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Trailer", "X-Resp-Trailer")
			fmt.Fprintf(w, "req-trailer=%s", r.Trailer.Get("X-Req-Trailer"))
			w.Header().Set("X-Resp-Trailer", "done")
			return
		case "/stream":
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "part%d\n", i)
				w.(http.Flusher).Flush()
			}
			return
		case "/own-alt-svc":
			w.Header().Set("Alt-Svc", "clear")
		}
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		w.Header().Set("X-Seen-Connection", r.Header.Get("Connection"))
		w.Header().Set("X-Seen-Close", fmt.Sprint(r.Close))
		fmt.Fprintf(w, "%s %s host=%s te=%v x=%s cookie=%s len=%d sha=%s",
			r.Method, r.RequestURI, r.Host, r.TransferEncoding, r.Header.Get("X-Test"), r.Header.Get("Cookie"), len(body), hex.EncodeToString(sum[:8]))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func buildH3Stack(t *testing.T) *h3Stack { return buildH3StackWith(t, 0, 0) }

// buildH3StackCapped is buildH3Stack with ingress.max_connections set.
func buildH3StackCapped(t *testing.T, maxConns int) *h3Stack { return buildH3StackWith(t, maxConns, 0) }

// buildH3StackWith is buildH3Stack with ingress.max_connections and
// ingress.read_header_timeout set.
func buildH3StackWith(t *testing.T, maxConns int, readHeader time.Duration) *h3Stack {
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
	acPEM, akPEM, _ := ca.IssueClient("agent")
	agentCert := writeFile(t, dir, "agent.crt", acPEM)
	agentKey := writeFile(t, dir, "agent.key", akPEM)
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &h3Stack{udpAddr: pc.LocalAddr().String(), roots: pool, edge: obs.NewState("edge"), agent: obs.NewState("agent"), udp: pc}
	edgeLog, _, _ := obs.NewLogger("error", "text", io.Discard)
	e, err := edge.New(&config.EdgeConfig{
		Ingress: config.IngressConfig{
			Mode:              "standalone",
			MaxConnections:    maxConns,
			ReadHeaderTimeout: config.Duration(readHeader),
			TLS:               config.TLSFiles{Cert: edgeCertPath, Key: edgeKeyPath}, // the edge's own cert, for 127.0.0.1
			HTTP3:             config.HTTP3Config{Enabled: true, Listen: st.udpAddr},
		},
		Tunnel: config.TunnelServerConfig{CA: caPath, Cert: edgeCertPath, Key: edgeKeyPath},
		Routes: []config.EdgeRoute{
			{Host: "*", AgentFingerprint: fingerprintOf(t, acPEM)},
		},
		Drain: config.Duration(2 * time.Second),
	}, edgeLog, st.edge)
	if err != nil {
		t.Fatal(err)
	}
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	ingressLn := tls.NewListener(plain, &tls.Config{Certificates: []tls.Certificate{edgeCert}})
	st.tcpAddr = plain.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	edgeCtx, stopEdge := context.WithCancel(ctx)
	st.stop = func() { stopEdge(); <-served }
	t.Cleanup(func() { cancel(); <-served })
	go func() { _ = e.ServeWithHTTP3(edgeCtx, tunLn, ingressLn, pc); close(served) }()

	agentLog, _, _ := obs.NewLogger("error", "text", io.Discard)
	ag, err := agent.New(&config.AgentConfig{
		Edge:      config.EdgeRef{Address: tunLn.Addr().String(), CA: caPath, Cert: agentCert, Key: agentKey},
		Routes:    []config.AgentRoute{{Host: "*", Service: echoBackend(t)}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
		Drain:     config.Duration(time.Second),
	}, agentLog, st.agent)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ag.Run(ctx) }()
	waitSessions(t, st.edge, 1)
	return st
}

func (s *h3Stack) h3Client(t *testing.T) *http.Client {
	t.Helper()
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1"}}
	t.Cleanup(func() { _ = tr.Close() })
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (s *h3Stack) url(path string) string { return "https://" + s.udpAddr + path }

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHTTP3RequestReachesTheBackendAsHTTP1(t *testing.T) {
	st := buildH3Stack(t)
	c := st.h3Client(t)

	req, _ := http.NewRequest(http.MethodGet, st.url("/a/b?q=1"), nil)
	req.Header.Set("X-Test", "yes")
	req.Header.Add("Cookie", "a=1")
	req.Header.Add("Cookie", "b=2")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.ProtoMajor != 3 || resp.StatusCode != 200 {
		t.Fatalf("proto %s status %d", resp.Proto, resp.StatusCode)
	}
	want := "GET /a/b?q=1 host=" + st.udpAddr + " te=[] x=yes cookie=a=1; b=2 len=0"
	if !strings.HasPrefix(body, want) {
		t.Fatalf("backend saw %q, want prefix %q", body, want)
	}
	if resp.Header.Get("X-Seen-Close") != "true" {
		t.Fatal("the backend must get Connection: close (one request per stream)")
	}
	if resp.Header.Get("Connection") != "" {
		t.Fatalf("a connection-level header crossed: %v", resp.Header)
	}

	// Bodies: a known length, and an unknown one (sent chunked).
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	sum := sha256.Sum256(big)
	resp, err = c.Post(st.url("/up"), "application/octet-stream", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); !strings.Contains(body, fmt.Sprintf("len=%d sha=%s", len(big), hex.EncodeToString(sum[:8]))) {
		t.Fatalf("known-length body: %q", body)
	}
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 16; i++ {
			_, _ = pw.Write(big[i*(1<<16) : (i+1)*(1<<16)])
		}
		_ = pw.Close()
	}()
	req, _ = http.NewRequest(http.MethodPut, st.url("/up"), pr) // no length: ContentLength -1
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); !strings.Contains(body, "te=[chunked]") || !strings.Contains(body, fmt.Sprintf("len=%d sha=%s", len(big), hex.EncodeToString(sum[:8]))) {
		t.Fatalf("unknown-length body: %q", body)
	}

	// A streamed response arrives in full.
	resp, err = c.Get(st.url("/stream"))
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); body != "part0\npart1\npart2\n" {
		t.Fatalf("streamed body: %q", body)
	}

	// Counted as HTTP/3 streams on the route.
	for _, r := range st.edge.Detail().Routes {
		if r.Pattern == "*" && r.TotalH3 < 4 {
			t.Fatalf("HTTP/3 streams counted: %d, want at least 4", r.TotalH3)
		}
	}
}

func TestHTTP3RefusesConnect(t *testing.T) {
	st := buildH3Stack(t)
	req, _ := http.NewRequest(http.MethodConnect, st.url("/"), nil)
	req.Host = "example.com:443"
	resp, err := st.h3Client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)
	if resp.StatusCode != 501 {
		t.Fatalf("CONNECT status = %d, want 501", resp.StatusCode)
	}
}

// The TCP ingress advertises HTTP/3 in the first response on a connection,
// and leaves a service's own Alt-Svc alone.
func TestAltSvcOnTCP(t *testing.T) {
	st := buildH3Stack(t)
	dial := func() (*tls.Conn, *bufio.Reader) {
		c, err := tls.Dial("tcp", st.tcpAddr, &tls.Config{RootCAs: st.roots, ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c, bufio.NewReader(c)
	}
	do := func(c *tls.Conn, br *bufio.Reader, path string) *http.Response {
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	_, port, _ := net.SplitHostPort(st.udpAddr)
	want := `h3=":` + port + `"; ma=86400`
	c, br := dial()
	if got := do(c, br, "/").Header.Get("Alt-Svc"); got != want {
		t.Fatalf("Alt-Svc = %q, want %q", got, want)
	}
	if got := do(c, br, "/").Header.Get("Alt-Svc"); got != "" {
		t.Fatalf("a later response on the same connection got Alt-Svc %q", got)
	}
	first := c
	c, br = dial()
	if got := do(c, br, "/own-alt-svc").Header.Values("Alt-Svc"); len(got) != 1 || got[0] != "clear" {
		t.Fatalf("the service's own Alt-Svc was changed: %q", got)
	}
	// The edge counts tunnel traffic, not the header it added: once the
	// streams have closed, both ends report the same bytes.
	_ = first.Close()
	_ = c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e, a := st.edge.Snapshot(), st.agent.Snapshot()
		if e.ActiveStreams == 0 && a.ActiveStreams == 0 && e.BytesOut == a.BytesOut && e.BytesIn == a.BytesIn {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("edge in/out %d/%d, agent %d/%d", e.BytesIn, e.BytesOut, a.BytesIn, a.BytesOut)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ingress.max_connections caps QUIC connections as it caps TCP ones; the
// requests a connection multiplexes share its slot.
func TestHTTP3ConnectionsAreCapped(t *testing.T) {
	st := buildH3StackCapped(t, 1)
	first := st.h3Client(t)
	resp, err := first.Get(st.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)
	// While one request is in flight on the connection, a second one on it
	// is served too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow, _ := http.NewRequestWithContext(ctx, http.MethodGet, st.url("/slow"), nil)
	go func() {
		if resp, err := first.Do(slow); err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for st.edge.Snapshot().ActiveStreams == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the slow request never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err = first.Get(st.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	if _ = readAll(t, resp); resp.StatusCode != 200 {
		t.Fatalf("a second concurrent request on the same connection: %d, want 200 (it shares the connection's slot)", resp.StatusCode)
	}
	cancel()
	if _, err := st.h3Client(t).Get(st.url("/")); err == nil {
		t.Fatal("a second QUIC connection over the cap was served")
	}
	if got := st.edge.Detail().UnroutedFailures.Get(obs.ReasonMaxConnections); got < 1 {
		t.Fatalf("max_connections rejections = %d", got)
	}
	// The first connection keeps working.
	resp, err = first.Get(st.url("/"))
	if err != nil {
		t.Fatalf("the connection within the cap: %v", err)
	}
	_ = readAll(t, resp)
}

// If HTTP/3 stops while TCP carries on, TCP responses stop advertising it.
func TestAltSvcWithdrawnWhenHTTP3Stops(t *testing.T) {
	st := buildH3Stack(t)
	_ = st.udp.Close() // the UDP socket breaks
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := tls.Dial("tcp", st.tcpAddr, &tls.Config{RootCAs: st.roots, ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		_ = c.Close()
		if resp.Header.Get("Alt-Svc") == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Alt-Svc still advertised after HTTP/3 stopped")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A client that gives up on a request frees its tunnel stream at once,
// rather than when the backend answers.
func TestHTTP3CancelledRequestEndsItsStream(t *testing.T) {
	st := buildH3Stack(t)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, st.url("/slow"), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := st.h3Client(t).Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for st.edge.Snapshot().ActiveStreams == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the request never reached the tunnel")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	deadline = time.Now().Add(2 * time.Second) // well before the backend's 5s
	for st.edge.Snapshot().ActiveStreams != 0 || st.agent.Snapshot().ActiveStreams != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("streams still open after the client gave up: edge %d, agent %d", st.edge.Snapshot().ActiveStreams, st.agent.Snapshot().ActiveStreams)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Trailers cross in both directions.
func TestHTTP3Trailers(t *testing.T) {
	st := buildH3Stack(t)
	req, _ := http.NewRequest(http.MethodPost, st.url("/trailers"), strings.NewReader("payload"))
	req.Trailer = http.Header{"X-Req-Trailer": {"sent"}}
	resp, err := st.h3Client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); body != "req-trailer=sent" {
		t.Fatalf("the backend saw %q", body)
	}
	if got := resp.Trailer.Get("X-Resp-Trailer"); got != "done" {
		t.Fatalf("response trailer = %q, want done (trailers: %v)", got, resp.Trailer)
	}
}

// A QUIC connection that opens a stream but never sends a request is closed
// after read_header_timeout, rather than holding its slot for as long as it
// keeps the connection alive.
func TestHTTP3ConnectionWithoutARequestIsClosed(t *testing.T) {
	st := buildH3StackWith(t, 0, 300*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, st.udpAddr, &tls.Config{RootCAs: st.roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}}, &quic.Config{KeepAlivePeriod: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	str, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = str.Write([]byte{0x01}) // the start of a HEADERS frame, and nothing more
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a connection with no request in progress was kept open")
	}
}

// openWebSocket opens a WebSocket over HTTP/3 (RFC 9220) to path.
func (s *h3Stack) openWebSocket(t *testing.T, path string) (*http3.RequestStream, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1"}}
	t.Cleanup(func() { _ = tr.Close() })
	qc, err := quic.DialAddr(ctx, s.udpAddr, http3.ConfigureTLSConfig(&tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1"}), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") }) // or the edge's shutdown waits out its drain for it
	cc := tr.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no SETTINGS from the edge")
	}
	if !cc.Settings().EnableExtendedConnect {
		t.Fatal("the edge does not offer extended CONNECT")
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(s.url(path))
	req := &http.Request{Method: http.MethodConnect, Proto: "websocket", URL: u, Host: u.Host,
		Header: http.Header{"Sec-Websocket-Version": {"13"}, "Sec-Websocket-Protocol": {"chat"}}}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	return str, resp
}

// A WebSocket over HTTP/3 reaches the backend as an HTTP/1.1 upgrade, and
// frames pass both ways.
func TestHTTP3WebSocket(t *testing.T) {
	st := buildH3Stack(t)
	str, resp := st.openWebSocket(t, "/ws")
	if resp.StatusCode != 200 || resp.Header.Get("Sec-Websocket-Protocol") != "chat" {
		t.Fatalf("upgrade answered %d %v", resp.StatusCode, resp.Header)
	}
	for _, msg := range []string{"\x81\x05hello", "\x81\x05world"} {
		if _, err := str.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(str, got); err != nil || string(got) != msg {
			t.Fatalf("echo = %q, %v", got, err)
		}
	}
	if d := st.edge.Detail(); d.Routes[0].TotalH3 < 1 {
		t.Fatal("the WebSocket is not counted as an HTTP/3 stream")
	}
	_ = str.Close()

	// A service that turns the upgrade down is heard.
	_, resp = st.openWebSocket(t, "/ws-deny")
	if resp.StatusCode != 403 {
		t.Fatalf("a refused upgrade: %d, want the service's 403", resp.StatusCode)
	}
}

// A WebSocket the client closes is released as soon as the backend has
// finished the closing handshake.
func TestHTTP3WebSocketClientCloseIsPrompt(t *testing.T) {
	st := buildH3Stack(t)
	str, resp := st.openWebSocket(t, "/ws")
	if resp.StatusCode != 200 {
		t.Fatalf("upgrade: %d", resp.StatusCode)
	}
	if _, err := str.Write([]byte("\x81\x02hi")); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadFull(str, make([]byte, 4))
	start := time.Now()
	if _, err := str.Write([]byte("\x88\x00")); err != nil { // the client's Close frame
		t.Fatal(err)
	}
	_ = str.Close() // and the end of its side; the backend answers and hangs up
	deadline := time.Now().Add(10 * time.Second)
	for st.edge.Snapshot().ActiveStreams != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the WebSocket never ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("ended after %v: the edge waited although the backend had finished", d)
	}
}

// A streamed response's status and headers reach the client at once, not
// with its first body bytes.
func TestHTTP3StreamedHeadersAtOnce(t *testing.T) {
	st := buildH3Stack(t)
	start := time.Now()
	resp, err := st.h3Client(t).Get(st.url("/held"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if d := time.Since(start); d > time.Second || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("headers after %v (%v): held back with the body", d, resp.Header)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "data: late\n\n" {
		t.Fatalf("body %q", b)
	}
}

// Shutdown holds HTTP/3 requests to the drain budget: one still waiting on
// its service when the budget is spent is ended with the agent sessions.
func TestHTTP3ShutdownKeepsToTheDrainBudget(t *testing.T) {
	st := buildH3Stack(t) // drain_timeout 2s
	go func() {
		if resp, err := st.h3Client(t).Get(st.url("/slow")); err == nil { // 5s
			_ = resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for st.edge.Snapshot().ActiveStreams == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the request never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	st.stop()
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("shutdown took %v, past the 2s drain budget", d)
	}
}
