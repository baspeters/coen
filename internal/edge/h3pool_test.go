package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/obs/obstest"
	"github.com/baspeters/coen/internal/tunnel"
)

// kaAgent serves every stream it is given as a keep-alive backend would:
// after the preamble it reads requests one after another and answers each
// with answer(stream, n, request), stream and n counting from 1. An answer
// of "" ends the stream without one; one ending in closeAfter is sent, then
// the stream ends (the backend closing its connection).
type kaAgent struct {
	streams atomic.Int32
	reqs    atomic.Int32
}

func runKAAgent(cli *yamux.Session, answer func(stream, n int, r *http.Request) string) *kaAgent {
	a := &kaAgent{}
	go func() {
		for {
			s, err := cli.AcceptStream()
			if err != nil {
				return
			}
			id := int(a.streams.Add(1))
			go func() {
				defer s.Close()
				if tunnel.Accept(s) != nil {
					return
				}
				if _, err := tunnel.ReadPreamble(s); err != nil {
					return
				}
				br := bufio.NewReader(s)
				for n := 1; ; n++ {
					r, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, r.Body)
					a.reqs.Add(1)
					reply := answer(id, n, r)
					if reply == "" {
						return
					}
					last := strings.HasSuffix(reply, closeAfter)
					if _, err := io.WriteString(s, strings.TrimSuffix(reply, closeAfter)); err != nil || last {
						return
					}
				}
			}()
		}
	}()
	return a
}

const closeAfter = "\x00close"

// okReply is a keep-alive response naming the stream and request it came on.
func okReply(stream, n int, r *http.Request) string {
	body := fmt.Sprintf("s%d r%d %s close=%v", stream, n, r.Method, r.Close)
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

// poolEdge is an edge with stream reuse and one v2 agent served by answer.
func poolEdge(t *testing.T, answer func(stream, n int, r *http.Request) string) (*Edge, *routeState, *obs.State, *kaAgent, *agentConn) {
	t.Helper()
	st := obs.NewState("edge")
	e, rs := h3Edge(st)
	e.h3pool = newH3Pool()
	srv, cli := newServerSession(t)
	t.Cleanup(func() { _ = cli.Close() })
	a := runKAAgent(cli, answer)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	return e, rs, st, a, c
}

// newPoolConn is one HTTP/3 connection's pool; it ends with the test.
func newPoolConn(t *testing.T, e *Edge) (*connStreams, context.Context) {
	t.Helper()
	gone, end := context.WithCancel(context.Background())
	t.Cleanup(end)
	cs := e.h3pool.newConn(gone)
	return cs, context.WithValue(context.Background(), connStreamsKey{}, cs)
}

// deadlineRecorder is a response recorder whose request side takes read
// deadlines, as an HTTP/3 one does, so small bodies can be held for a resend.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func (deadlineRecorder) SetReadDeadline(time.Time) error { return nil }

func do(e *Edge, ctx context.Context, method string, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := h3Request(method, "app.test", rd).WithContext(ctx)
	rec := httptest.NewRecorder()
	e.serveHTTP3(deadlineRecorder{rec}, r)
	return rec
}

// waitFor polls cond for up to 2s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); !cond(); {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func routeSnap(st *obs.State) obs.RouteSnapshot { return st.Detail().Routes[0] }

// A connection's requests share one stream in turn, kept alive; another
// connection gets its own.
func TestH3PoolReusesStreamPerConnection(t *testing.T) {
	e, _, st, a, _ := poolEdge(t, okReply)
	_, ctx := newPoolConn(t, e)
	for i, m := range []string{"GET", "PUT", "DELETE"} {
		body := ""
		if m == "PUT" {
			body = "hello"
		}
		rec := do(e, ctx, m, body)
		if want := fmt.Sprintf("s1 r%d %s close=false", i+1, m); rec.Code != 200 || rec.Body.String() != want {
			t.Fatalf("request %d: %d %q, want %q", i+1, rec.Code, rec.Body.String(), want)
		}
	}
	_, other := newPoolConn(t, e)
	if rec := do(e, other, "GET", ""); rec.Body.String() != "s2 r1 GET close=false" {
		t.Fatalf("another connection must get its own stream: %q", rec.Body.String())
	}
	snap := routeSnap(st)
	if snap.TotalH3 != 2 || snap.ReqH3 != 4 || snap.Active != 2 {
		t.Fatalf("streams %d, requests %d, active %d; want 2, 4, 2", snap.TotalH3, snap.ReqH3, snap.Active)
	}
	if a.streams.Load() != 2 {
		t.Fatalf("the agent saw %d streams", a.streams.Load())
	}
}

// A kept stream whose service ends the connection just as the next request
// goes out: nothing comes back, so the request goes again on a fresh stream,
// without the client seeing a failure.
func TestH3PoolStaleStreamIsRetried(t *testing.T) {
	for _, m := range []string{"GET", "PUT"} {
		e, _, st, a, _ := poolEdge(t, func(stream, n int, r *http.Request) string {
			if stream == 1 && n == 2 {
				return "" // closed under the request
			}
			return okReply(stream, n, r)
		})
		_, ctx := newPoolConn(t, e)
		body := ""
		if m == "PUT" {
			body = "small"
		}
		do(e, ctx, m, body)
		rec := do(e, ctx, m, body)
		if rec.Code != 200 || rec.Body.String() != "s2 r1 "+m+" close=false" {
			t.Fatalf("%s: %d %q", m, rec.Code, rec.Body.String())
		}
		if got := routeSnap(st).ReqH3; got != 2 {
			t.Fatalf("%s: %d requests counted, want 2 (a resend is the same request)", m, got)
		}
		if a.reqs.Load() != 3 || routeSnap(st).Failures.Get(obs.ReasonStreamError) != 0 {
			t.Fatalf("%s: requests seen %d, stream errors %d", m, a.reqs.Load(), routeSnap(st).Failures.Get(obs.ReasonStreamError))
		}
	}
}

// A request that cannot be sent twice (its body too large to hold) never
// takes a kept stream, so it never meets one that has closed.
func TestH3PoolLargeBodyTakesFreshStream(t *testing.T) {
	e, _, _, _, _ := poolEdge(t, okReply)
	_, ctx := newPoolConn(t, e)
	do(e, ctx, "GET", "")
	rec := do(e, ctx, "POST", strings.Repeat("x", maxHeldBody+1))
	if rec.Body.String() != "s2 r1 POST close=false" {
		t.Fatalf("a large upload must go on a fresh stream: %q", rec.Body.String())
	}
	// Once done, its stream is kept like any other.
	if rec := do(e, ctx, "GET", ""); !strings.HasSuffix(rec.Body.String(), "r2 GET close=false") {
		t.Fatalf("got %q", rec.Body.String())
	}
}

// A stream is not kept when the service closes its connection, when its
// response can only end that way, or when it sends more than its response.
func TestH3PoolNotKept(t *testing.T) {
	for name, reply := range map[string]string{
		"connection close": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
		"no length":        "HTTP/1.1 200 OK\r\n\r\nok" + closeAfter, // the body ends with the connection
		"http/1.0":         "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"extra bytes":      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\n",
	} {
		e, _, st, _, _ := poolEdge(t, func(stream, n int, r *http.Request) string {
			if stream == 1 {
				return reply
			}
			return okReply(stream, n, r)
		})
		_, ctx := newPoolConn(t, e)
		if rec := do(e, ctx, "GET", ""); rec.Code != 200 || rec.Body.String() != "ok" {
			t.Fatalf("%s: %d %q", name, rec.Code, rec.Body.String())
		}
		if rec := do(e, ctx, "GET", ""); rec.Body.String() != "s2 r1 GET close=false" {
			t.Fatalf("%s: the stream was kept: %q", name, rec.Body.String())
		}
		waitFor(t, name+": the first stream closed", func() bool { return routeSnap(st).Active == 1 })
	}
}

func idleCount(e *Edge) int {
	e.h3pool.mu.Lock()
	defer e.h3pool.mu.Unlock()
	return len(e.h3pool.all)
}

// The watcher drops a kept stream as soon as the service ends it, releasing
// all it holds, and the next request opens a fresh one.
func TestH3PoolDropsStreamTheServiceEnds(t *testing.T) {
	e, rs, st, _, _ := poolEdge(t, func(stream, n int, r *http.Request) string {
		if stream == 1 {
			return okReply(stream, n, r) + closeAfter // then the idle connection ends
		}
		return okReply(stream, n, r)
	})
	rs.sem = newSemaphore(1)
	_, ctx := newPoolConn(t, e)
	do(e, ctx, "GET", "")
	waitFor(t, "the dropped stream to release its slot", func() bool {
		return idleCount(e) == 0 && routeSnap(st).Active == 0 && rs.sem.tryAcquire()
	})
	rs.sem.release()
	if rec := do(e, ctx, "GET", ""); rec.Body.String() != "s2 r1 GET close=false" {
		t.Fatalf("got %q", rec.Body.String())
	}
}

// A kept stream holds a slot of its route's cap, but gives it up to a
// request that needs one: another connection's request does not wait.
func TestH3PoolSlotGoesToWaitingRequest(t *testing.T) {
	e, rs, _, _, _ := poolEdge(t, okReply)
	rs.sem = newSemaphore(1)
	_, a := newPoolConn(t, e)
	_, b := newPoolConn(t, e)
	do(e, a, "GET", "")
	start := time.Now()
	if rec := do(e, b, "GET", ""); rec.Code != 200 || rec.Body.String() != "s2 r1 GET close=false" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the request waited %v for a slot a kept stream held", d)
	}
	if rec := do(e, a, "GET", ""); rec.Code != 200 || rec.Body.String() != "s3 r1 GET close=false" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	// While a request waits for a slot, a finished stream is not kept.
	rs.slotWaiters.Add(1)
	defer rs.slotWaiters.Add(-1)
	if do(e, a, "GET", ""); idleCount(e) != 0 {
		t.Fatalf("a stream was kept while a request waited: %d idle", idleCount(e))
	}
}

// Kept streams close with their connection, when their agent drains, and
// when the edge drains (which keeps no more), and after keep.
func TestH3PoolCloses(t *testing.T) {
	e, _, st, _, c := poolEdge(t, okReply)
	gone, end := context.WithCancel(context.Background())
	cs := e.h3pool.newConn(gone)
	ctx := context.WithValue(context.Background(), connStreamsKey{}, cs)
	do(e, ctx, "GET", "")
	end()
	waitFor(t, "the connection's streams to close", func() bool { return idleCount(e) == 0 && routeSnap(st).Active == 0 })
	if do(e, ctx, "GET", ""); idleCount(e) != 0 {
		t.Fatal("a stream was kept for a connection that has ended")
	}

	_, ctx = newPoolConn(t, e)
	do(e, ctx, "GET", "")
	e.retire(c)
	if idleCount(e) != 0 {
		t.Fatal("a draining agent's stream was kept")
	}

	e2, _, _, _, _ := poolEdge(t, okReply)
	_, ctx = newPoolConn(t, e2)
	do(e2, ctx, "GET", "")
	e2.h3pool.closeAll()
	if do(e2, ctx, "GET", ""); idleCount(e2) != 0 {
		t.Fatal("a stream was kept while the edge drains")
	}

	e3, _, st3, _, _ := poolEdge(t, okReply)
	e3.cfg.Ingress.IdleTimeout = config.Duration(50 * time.Millisecond)
	_, ctx = newPoolConn(t, e3)
	do(e3, ctx, "GET", "")
	waitFor(t, "an idle stream to expire", func() bool { return idleCount(e3) == 0 && routeSnap(st3).Active == 0 })
}

// A stream is only taken for its own route.
func TestH3PoolTakeChecksRoute(t *testing.T) {
	e, rs, _, _, _ := poolEdge(t, okReply)
	cs, ctx := newPoolConn(t, e)
	do(e, ctx, "GET", "")
	other := &routeState{}
	if ts := e.h3pool.take(cs, "app.test", other); ts != nil {
		t.Fatal("a stream was taken for another route")
	}
	if idleCount(e) != 0 {
		t.Fatal("a stream found unusable must be closed")
	}
	if ts := e.h3pool.take(cs, "app.test", rs); ts != nil {
		t.Fatal("nothing should be left")
	}
	var nilPool *h3Pool
	if nilPool.take(cs, "app.test", rs) != nil || nilPool.evictRoute(rs) || nilPool.newConn(context.Background()) != nil {
		t.Fatal("a nil pool keeps nothing")
	}
	nilPool.closeAll()
	nilPool.closeAgent(nil)
}

// A connection keeps at most maxKeptPerConn streams; past that, finished
// streams close.
func TestH3PoolKeepsAtMostItsShare(t *testing.T) {
	e, rs, st, _, c := poolEdge(t, okReply)
	cs, _ := newPoolConn(t, e)
	for i := 0; i < maxKeptPerConn+3; i++ {
		s, err := c.sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.AwaitAccept(s, time.Second); err != nil { // as dispatch does
			t.Fatal(err)
		}
		c.stat.Reserve()
		c.stat.Commit()
		e.state.StreamOpenedHTTP3(rs.stats)
		e.h3pool.put(cs, &tunnelStream{e: e, s: s, agent: c, rs: rs, host: "app.test"}, time.Minute)
	}
	if n := idleCount(e); n != maxKeptPerConn {
		t.Fatalf("%d streams kept, want %d", n, maxKeptPerConn)
	}
	if a := routeSnap(st).Active; a != maxKeptPerConn {
		t.Fatalf("%d streams open, want %d", a, maxKeptPerConn)
	}
}

// A request that never reaches a stream is not counted as sent.
func TestH3RequestCountedWhenSent(t *testing.T) {
	st := obs.NewState("edge")
	e, _ := h3Edge(st)
	e.h3pool = newH3Pool()
	rec := httptest.NewRecorder()
	e.serveHTTP3(rec, h3Request("GET", "app.test", nil)) // no agent
	if rec.Code != 502 || routeSnap(st).ReqH3 != 0 {
		t.Fatalf("%d, %d requests counted", rec.Code, routeSnap(st).ReqH3)
	}
}

// A request that must not be sent twice (a POST) never takes a kept stream,
// so it is never resent; its fresh stream is kept for later requests.
func TestH3PoolPostNeverResent(t *testing.T) {
	e, _, st, a, _ := poolEdge(t, okReply)
	_, ctx := newPoolConn(t, e)
	do(e, ctx, "GET", "")
	if rec := do(e, ctx, "POST", "order"); rec.Body.String() != "s2 r1 POST close=false" {
		t.Fatalf("a POST must go on a fresh stream: %q", rec.Body.String())
	}
	if rec := do(e, ctx, "POST", "order"); rec.Code != 200 || rec.Body.String() != "s3 r1 POST close=false" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	// Idempotent requests take the kept streams, most recent first.
	if rec := do(e, ctx, "GET", ""); rec.Body.String() != "s3 r2 GET close=false" {
		t.Fatalf("got %q", rec.Body.String())
	}
	// A POST marked with an idempotency key may take a kept stream.
	r := h3Request("POST", "app.test", strings.NewReader("order")).WithContext(ctx)
	r.Header.Set("Idempotency-Key", "k1")
	rec := httptest.NewRecorder()
	e.serveHTTP3(deadlineRecorder{rec}, r)
	if rec.Body.String() != "s3 r3 POST close=false" {
		t.Fatalf("got %q", rec.Body.String())
	}
	if got := routeSnap(st).ReqH3; got != 5 || a.reqs.Load() != 5 {
		t.Fatalf("%d requests counted, %d seen by the agent; want 5 and 5", got, a.reqs.Load())
	}
}

// A TCP connection that finds its route full takes the slot of a stream
// kept for an HTTP/3 connection, rather than getting a 503.
func TestTCPTakesSlotFromKeptStream(t *testing.T) {
	e, rs, _, _, _ := poolEdge(t, okReply)
	rs.sem = newSemaphore(1)
	_, ctx := newPoolConn(t, e)
	do(e, ctx, "GET", "")
	if idleCount(e) != 1 {
		t.Fatal("the stream was not kept")
	}
	if !e.tcpRouteSlot(rs) {
		t.Fatal("a TCP connection was refused while only a kept stream held the slot")
	}
	if idleCount(e) != 0 {
		t.Fatal("the kept stream should have given up its slot")
	}
	if e.tcpRouteSlot(rs) {
		t.Fatal("the route is full: a second connection must be refused")
	}
	rs.sem.release()
}
