package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/obs/obstest"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// h3Edge is an edge with one route, app.test, served by fingerprint "A".
func h3Edge(st *obs.State) (*Edge, *routeState) {
	rs := &routeState{fingerprints: []string{"A"}, label: "A", stats: st.Route("app.test")}
	return &Edge{
		cfg:    &config.EdgeConfig{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "app.test", Value: rs}}),
	}, rs
}

// fakeAgent answers one stream: it takes it (v2), reads the preamble and the
// request head, records the head, and writes reply.
func fakeAgent(cli *yamux.Session, v2 bool, reply string, gotHead chan<- string) {
	s, err := cli.AcceptStream()
	if err != nil {
		return
	}
	defer s.Close()
	if v2 && tunnel.Accept(s) != nil {
		return
	}
	if _, err := tunnel.ReadPreamble(s); err != nil {
		return
	}
	br := bufio.NewReader(s)
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil || line == "\r\n" {
			break
		}
	}
	gotHead <- head.String()
	_, _ = io.WriteString(s, reply)
}

// interimRecorder records interim (1xx) responses apart from the final one,
// as an HTTP/3 response writer sends them (httptest's recorder would take a
// 1xx for the final status).
type interimRecorder struct {
	*httptest.ResponseRecorder
	interim []int
}

func (r *interimRecorder) WriteHeader(code int) {
	if code < 200 {
		r.interim = append(r.interim, code)
		return
	}
	r.ResponseRecorder.WriteHeader(code)
}

func h3Request(method, host string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, "https://"+host+"/x", body)
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/3.0", 3, 0
	r.RequestURI = "/x"
	return r
}

func TestServeHTTP3Answers(t *testing.T) {
	for _, v2 := range []bool{true, false} {
		st := obs.NewState("edge")
		e, _ := h3Edge(st)
		srv, cli := newServerSession(t)
		defer cli.Close()
		heads := make(chan string, 1)
		go fakeAgent(cli, v2, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 201 Created\r\nX-Up: 1\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok", heads)
		_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: v2})
		rec := &interimRecorder{ResponseRecorder: httptest.NewRecorder()}
		r := h3Request("POST", "app.test", strings.NewReader("body"))
		r.Header.Set("Expect", "100-continue")
		e.serveHTTP3(rec, r)
		if len(rec.interim) != 2 || rec.interim[0] != 100 || rec.interim[1] != 103 {
			t.Fatalf("v2=%v: interim responses not relayed: %v", v2, rec.interim)
		}
		if rec.Header().Get("Link") != "" {
			t.Fatalf("v2=%v: an interim response's header leaked into the final one", v2)
		}
		if rec.Code != 201 || rec.Body.String() != "ok" || rec.Header().Get("X-Up") != "1" || rec.Header().Get("Connection") != "" {
			t.Fatalf("v2=%v: %d %q %v", v2, rec.Code, rec.Body.String(), rec.Header())
		}
		if h := <-heads; !strings.HasPrefix(h, "POST /x HTTP/1.1\r\nHost: app.test\r\n") || !strings.Contains(h, "Expect: 100-continue\r\n") {
			t.Fatalf("v2=%v: agent got head %q", v2, h)
		}
		if d := st.Detail(); d.Routes[0].TotalH3 != 1 {
			t.Fatalf("v2=%v: HTTP/3 streams %d", v2, d.Routes[0].TotalH3)
		}
	}
}

func TestServeHTTP3Refusals(t *testing.T) {
	st := obs.NewState("edge")
	e, rs := h3Edge(st)
	try := func(r *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.serveHTTP3(rec, r)
		return rec
	}
	if rec := try(h3Request("GET", "other.test", nil)); rec.Code != 404 {
		t.Fatalf("no route: %d", rec.Code)
	}
	if rec := try(h3Request("GET", "app.test", nil)); rec.Code != 502 || !strings.Contains(rec.Body.String(), "No agent connected") {
		t.Fatalf("no agent: %d %q", rec.Code, rec.Body.String())
	}
	bad := h3Request("GET", "app.test", nil)
	bad.Header.Set("X-Bad", "a\nb")
	if rec := try(bad); rec.Code != 400 {
		t.Fatalf("bad header: %d", rec.Code)
	}
	// A full route: the request waits read_header_timeout for a slot, then
	// gets 503. (The global cap counts QUIC connections; see the e2e test.)
	e.cfg.Ingress.ReadHeaderTimeout = config.Duration(50 * time.Millisecond)
	rs.sem = newSemaphore(1)
	rs.sem.tryAcquire()
	start := time.Now()
	if rec := try(h3Request("GET", "app.test", nil)); rec.Code != 503 || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("route cap: %d after %v", rec.Code, time.Since(start))
	}
}

// A request that cannot be served is answered at once, even when its body
// (of unknown length) has not ended: the body is only looked at for a
// request that goes to an agent.
func TestServeHTTP3AnswersRefusalsWithoutWaitingForTheBody(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	r := h3Request("POST", "other.test", nil)
	r.Body = &slowBody{r: strings.NewReader("x"), delay: 2 * time.Second}
	r.ContentLength = -1
	start := time.Now()
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, r)
	if rec.Code != 404 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("status %d after %v", rec.Code, time.Since(start))
	}
}

func TestServeHTTP3BadAndCutResponses(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	heads := make(chan string, 2)

	go fakeAgent(cli, true, "not http", heads)
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "Invalid response") {
		t.Fatalf("bad response: %d %q", rec.Code, rec.Body.String())
	}

	go fakeAgent(cli, true, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", heads)
	rec = httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("a cut response must abort the handler, got %v", v)
			}
		}()
		e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	}()
	if rec.Code != 200 || rec.Body.String() != "abc" {
		t.Fatalf("cut response: %d %q", rec.Code, rec.Body.String())
	}
}

// Over HTTP/3, a request to a full route waits for a slot rather than
// failing at once, and gives up after the wait or with its client.
func TestRouteSlotWaits(t *testing.T) {
	e, rs := h3Edge(obs.NewState("edge"))
	rs.sem = newSemaphore(1)
	r := h3Request("GET", "app.test", nil)
	if !e.routeSlot(r, rs, time.Second) {
		t.Fatal("a free slot")
	}
	go func() { time.Sleep(50 * time.Millisecond); rs.sem.release() }()
	start := time.Now()
	if !e.routeSlot(r, rs, time.Second) || time.Since(start) < 40*time.Millisecond {
		t.Fatal("a request to a full route must wait for the slot to free")
	}
	if e.routeSlot(r, rs, 30*time.Millisecond) {
		t.Fatal("no slot within the wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e.routeSlot(r.WithContext(ctx), rs, time.Second) {
		t.Fatal("a client that has gone gets no slot")
	}
	rs.sem.release()
}

// silentAgent takes a stream, reads the request, and never answers.
func silentAgent(cli *yamux.Session) {
	s, err := cli.AcceptStream()
	if err != nil {
		return
	}
	defer s.Close()
	if tunnel.Accept(s) != nil {
		return
	}
	_, _ = io.Copy(io.Discard, s)
}

// A client that gives up is not a failure of the service, and a service
// that does not answer within ingress.idle_timeout gets a 504; neither
// counts as a stream error.
func TestServeHTTP3ClientGoneAndIdleTimeout(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})

	go silentAgent(cli)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("a client that has gone gets its stream reset, got %v", v)
			}
		}()
		e.serveHTTP3(rec, h3Request("GET", "app.test", nil).WithContext(ctx))
	}()
	if rec.Body.Len() != 0 {
		t.Fatalf("an answer was written for a client that had gone: %q", rec.Body.String())
	}

	go silentAgent(cli)
	e.cfg.Ingress.IdleTimeout = config.Duration(50 * time.Millisecond)
	rec = httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if rec.Code != 504 {
		t.Fatalf("no response within idle_timeout: %d, want 504", rec.Code)
	}
	f := st.Detail().Routes[0].Failures
	if f.Get(obs.ReasonStreamError) != 0 || f.Get(obs.ReasonResponseTimeout) != 1 {
		t.Fatalf("stream_error = %d (want 0), response_timeout = %d (want 1)", f.Get(obs.ReasonStreamError), f.Get(obs.ReasonResponseTimeout))
	}
}

func TestServeHTTP3RefusesConnectWith501(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("CONNECT", "app.test", nil))
	if rec.Code != 501 || st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest) != 0 {
		t.Fatalf("CONNECT: %d, bad_request %d", rec.Code, st.Detail().UnroutedFailures.Get(obs.ReasonBadRequest))
	}
}

// The edge does not invent a Content-Type the service did not send.
func TestServeHTTP3KeepsAMissingContentType(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	heads := make(chan string, 1)
	go fakeAgent(cli, true, "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 15\r\n\r\n<html>hi</html>", heads)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if v, ok := rec.Header()["Content-Type"]; !ok || len(v) != 0 {
		t.Fatalf("Content-Type = %v (present %v), want suppressed", v, ok)
	}
}

// A body that breaks off ends the request at once instead of leaving the
// service waiting for the rest.
func TestServeHTTP3TruncatedBody(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go silentAgent(cli)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	r := h3Request("POST", "app.test", strings.NewReader("abc"))
	r.ContentLength = 10 // promised 10, sends 3
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		e.serveHTTP3(httptest.NewRecorder(), r)
	}()
	select {
	case v := <-done:
		if v != http.ErrAbortHandler {
			t.Fatalf("got %v, want the stream reset", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the request hung on a truncated body")
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError); got != 0 {
		t.Fatalf("a client's broken body counted as a stream error (%d)", got)
	}
}

// A service that answers a WebSocket upgrade with a 2xx instead of 101 does
// not open the tunnel for the HTTP/3 client: it gets a 502.
func TestServeHTTP3WebSocketNot101(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	heads := make(chan string, 1)
	go fakeAgent(cli, true, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhtml", heads)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	r := h3Request("CONNECT", "app.test", nil)
	r.Proto, r.Host = "websocket", "app.test" // as quic-go presents an extended CONNECT
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, r)
	if rec.Code != 502 {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if h := <-heads; !strings.HasPrefix(h, "GET /x HTTP/1.1\r\n") || !strings.Contains(h, "Upgrade: websocket\r\n") || !strings.Contains(h, "Sec-WebSocket-Key: ") {
		t.Fatalf("the agent got %q", h)
	}
}

// A client that stalls its own body is not blamed on the service.
func TestServeHTTP3StalledBody(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	e.cfg.Ingress.IdleTimeout = config.Duration(100 * time.Millisecond)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go silentAgent(cli)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	pr, pw := io.Pipe()
	defer pw.Close()
	r := h3Request("POST", "app.test", pr)
	r.ContentLength = 10 // and nothing comes
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler {
				t.Fatalf("got %v, want the stream reset", v)
			}
		}()
		e.serveHTTP3(httptest.NewRecorder(), r)
	}()
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonResponseTimeout); got != 0 {
		t.Fatalf("a stalled client counted as a service timeout (%d)", got)
	}
}

// A backend whose response head never ends within the limit gets a 502,
// rather than being held in memory.
func TestServeHTTP3ResponseHeadLimit(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	heads := make(chan string, 1)
	go fakeAgent(cli, true, "HTTP/1.1 200 OK\r\nX-Big: "+strings.Repeat("a", 200<<10)+"\r\n\r\n", heads)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if rec.Code != 502 {
		t.Fatalf("an oversized response head: %d, want 502", rec.Code)
	}
}

// A tunnel that breaks during the upload is the service's side failing, not
// the client's: a 502 and a stream error.
func TestServeHTTP3TunnelBreaksDuringUpload(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() { // reads the head, then drops the stream
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		_ = tunnel.Accept(s)
		_, _ = tunnel.ReadPreamble(s)
		_ = s.Close()
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	body := strings.Repeat("x", 4<<20)
	r := h3Request("POST", "app.test", strings.NewReader(body))
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, r)
	if rec.Code != 502 || st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError) != 1 {
		t.Fatalf("status %d, stream_error %d; want 502 and 1", rec.Code, st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError))
	}
}

// An interim response before a WebSocket's 101 does not fail the upgrade.
func TestServeHTTP3WebSocketInterimBefore101(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() {
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		defer s.Close()
		_ = tunnel.Accept(s)
		_, _ = tunnel.ReadPreamble(s)
		req, err := http.ReadRequest(bufio.NewReader(s))
		if err != nil {
			return
		}
		fmt.Fprintf(s, "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(req.Header.Get("Sec-Websocket-Key")))
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	r := h3Request("CONNECT", "app.test", strings.NewReader(""))
	r.Proto, r.Host = "websocket", "app.test"
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status %d, want 200 (the tunnel open)", rec.Code)
	}
}

// A status below 100 is not a response the edge can relay: 502 bad_response.
func TestServeHTTP3StatusBelow100(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	heads := make(chan string, 1)
	go fakeAgent(cli, true, "HTTP/1.1 099 Odd\r\nContent-Length: 0\r\n\r\n", heads)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if rec.Code != 502 || st.Detail().Routes[0].Failures.Get(obs.ReasonBadResponse) != 1 {
		t.Fatalf("status %d, bad_response %d", rec.Code, st.Detail().Routes[0].Failures.Get(obs.ReasonBadResponse))
	}
}

// A service that stops reading the body and never answers is the service's
// timeout (504), not a client stall.
func TestServeHTTP3ServiceStopsReading(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	e.cfg.Ingress.IdleTimeout = config.Duration(200 * time.Millisecond)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() { // takes the head, then reads nothing more
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		defer s.Close()
		_ = tunnel.Accept(s)
		_, _ = tunnel.ReadPreamble(s)
		time.Sleep(5 * time.Second)
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	r := h3Request("POST", "app.test", strings.NewReader(strings.Repeat("x", 8<<20))) // far past the stream window
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, r)
	if rec.Code != 504 || st.Detail().Routes[0].Failures.Get(obs.ReasonResponseTimeout) != 1 {
		t.Fatalf("status %d, response_timeout %d; want 504 and 1", rec.Code, st.Detail().Routes[0].Failures.Get(obs.ReasonResponseTimeout))
	}
}

// Each response head gets the whole limit: several interim heads that add
// up to more than one head's limit still lead to the final response.
func TestServeHTTP3ManyInterimHeads(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	hint := "HTTP/1.1 103 Early Hints\r\nLink: </" + strings.Repeat("a", 50<<10) + ">\r\n\r\n"
	heads := make(chan string, 1)
	go fakeAgent(cli, true, hint+hint+hint+"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", heads)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	rec := &interimRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil))
	if rec.Code != 200 || rec.Body.String() != "ok" || len(rec.interim) != 3 {
		t.Fatalf("status %d body %q interim %v", rec.Code, rec.Body.String(), rec.interim)
	}
}

// stuckWriter is a client that has stopped reading: every write blocks until
// a write deadline is set.
type stuckWriter struct {
	h        http.Header
	deadline chan struct{}
	once     sync.Once
}

func (s *stuckWriter) Header() http.Header { return s.h }
func (s *stuckWriter) WriteHeader(int)     {}
func (s *stuckWriter) Flush()              {}
func (s *stuckWriter) Write(b []byte) (int, error) {
	<-s.deadline
	return 0, os.ErrDeadlineExceeded
}
func (s *stuckWriter) SetWriteDeadline(time.Time) error {
	s.once.Do(func() { close(s.deadline) })
	return nil
}

// A WebSocket whose client stops reading still ends once both sides are
// closed, rather than holding its handler (and slots) forever.
func TestServeHTTP3WebSocketStuckClient(t *testing.T) {
	old := closeGrace
	closeGrace = 50 * time.Millisecond
	defer func() { closeGrace = old }()
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() { // upgrades, then sends without end
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		defer s.Close()
		_ = tunnel.Accept(s)
		_, _ = tunnel.ReadPreamble(s)
		req, err := http.ReadRequest(bufio.NewReader(s))
		if err != nil {
			return
		}
		fmt.Fprintf(s, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", webSocketAccept(req.Header.Get("Sec-Websocket-Key")))
		for {
			if _, err := s.Write([]byte("\x81\x04ping")); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	r := h3Request("CONNECT", "app.test", strings.NewReader("")) // the client's side ends at once
	r.Proto, r.Host = "websocket", "app.test"
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		e.serveHTTP3(&stuckWriter{h: http.Header{}, deadline: make(chan struct{})}, r)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler hung on a client that stopped reading")
	}
}
