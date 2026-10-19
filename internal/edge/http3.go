package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http/httpguts"

	"github.com/baspeters/coen/internal/errpage"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
)

// HTTP/3 ingress. The edge terminates HTTP/3 itself and forwards each request
// over the tunnel as an HTTP/1.1 request, exactly like one arriving over TCP,
// so agents and the tunnel protocol are unchanged. A request's tunnel stream
// is kept for its connection's next request, as a TCP client's connection is
// (see h3pool.go). WebSockets over HTTP/3 (extended CONNECT) are bridged to an
// HTTP/1.1 upgrade (see http3ws.go).

// newHTTP3 returns the HTTP/3 server for the ingress certificate and a QUIC
// listener for it on its own transport over pc.
//
// Limits, set to match the TCP ingress:
//   - ingress.max_connections counts QUIC connections as it counts TCP ones
//     (see cappedListener). Each connection carries at most
//     maxStreamsPerConn requests at once; a client queues the rest itself,
//     as a browser does with its TCP connections.
//   - a route's max_connections counts streams to the backend, kept ones
//     included, as it counts TCP connections; requests over it wait for a
//     slot (see routeSlot), as a browser's queued requests would.
//   - keep-alives hold a connection open through a quiet response (a long
//     poll, server-sent events). A connection must start its first request
//     within ingress.read_header_timeout, and one with no request in progress
//     closes after ingress.idle_timeout (defaultHTTP3Idle when unset), even
//     if it holds a stream that never sent a request (see connActivity).
func (e *Edge) newHTTP3(cert tls.Certificate, pc net.PacketConn) (*http3.Server, *quic.Transport, *cappedListener, error) {
	idle := e.cfg.Ingress.IdleTimeout.Duration()
	if idle <= 0 {
		idle = defaultHTTP3Idle
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		GetConfigForClient: e.refuseNoHTTP3,
	})
	tr := &quic.Transport{Conn: pc, StatelessResetKey: resetKey(cert)}
	ln, err := tr.Listen(tlsConf, &quic.Config{
		HandshakeIdleTimeout: readHeaderDeadline(e.cfg.Ingress.ReadHeaderTimeout.Duration()),
		MaxIdleTimeout:       defaultHTTP3Idle,
		KeepAlivePeriod:      defaultHTTP3Idle / 3,
		MaxIncomingStreams:   maxStreamsPerConn,
	})
	if err != nil {
		_ = tr.Close()
		return nil, nil, nil, err
	}
	srv := &http3.Server{
		Handler:        http.HandlerFunc(e.serveHTTP3),
		MaxHeaderBytes: maxHeaderBytes,
		Logger:         e.log.With("component", "http3"),
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			ctx = context.WithValue(ctx, connStreamsKey{}, e.h3pool.newConn(c.Context()))
			return context.WithValue(ctx, connActivityKey{}, newConnActivity(c, readHeaderDeadline(e.cfg.Ingress.ReadHeaderTimeout.Duration()), idle))
		},
	}
	return srv, tr, &cappedListener{Listener: ln, e: e}, nil
}

// errNoHTTP3 refuses a QUIC handshake for a host kept off HTTP/3.
var errNoHTTP3 = errors.New("host not served over HTTP/3")

// refuseNoHTTP3 fails the QUIC handshake for a server name whose route is
// kept off HTTP/3 (routes[].http3: false), so the client falls back to TCP
// before sending a request. A handshake without a server name (a client
// that dialled an IP address) is matched as one, against the default route.
// Other names get the default config; a request on their connections for a
// host kept off HTTP/3 gets 421 (see serveHTTP3).
func (e *Edge) refuseNoHTTP3(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	rs, ok := e.routes.Match(hello.ServerName) // Match normalizes it
	if !ok || !rs.noHTTP3 {
		return nil, nil
	}
	// Not counted: a ClientHello is not a request, and its source address is
	// not yet validated, so anyone could drive a counter up with it.
	if e.log.Enabled(context.Background(), slog.LevelDebug) {
		addr := ""
		if hello.Conn != nil {
			addr = hello.Conn.RemoteAddr().String()
		}
		e.log.Debug("ingress.http3_handshake_refused", "server_name", hello.ServerName, "client_addr", addr)
	}
	return nil, errNoHTTP3
}

// resetKey derives the QUIC stateless reset key from the ingress
// certificate's private key, so it is the same across restarts: a client
// whose connection the edge forgot (after a restart) is reset at once rather
// than left to time out. It returns nil (resets off) if the key cannot be
// read.
func resetKey(cert tls.Certificate) *quic.StatelessResetKey {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte("coen quic stateless reset key"))
	var k quic.StatelessResetKey
	copy(k[:], mac.Sum(nil))
	return &k
}

// maxStreamsPerConn is how many requests one HTTP/3 connection may have in
// flight; a client queues further ones until a stream frees up. A client
// gets credit for a new stream only a round trip after one ends, so a limit
// a page load reaches (many small assets at once) costs every request past
// it that round trip: this is quic-go's default, as most servers allow.
const maxStreamsPerConn = 100

// maxKeptPerConn is how many tunnel streams (each a backend connection) an
// HTTP/3 connection keeps for its next requests (see h3Pool); a burst beyond
// it opens fresh streams for the rest.
const maxKeptPerConn = 32

// cappedListener applies the global connection cap to QUIC connections, and
// once the edge drains, turns new connections away at once (a client then
// fails over, rather than waiting out its handshake timeout).
type cappedListener struct {
	*quic.Listener
	e        *Edge
	draining atomic.Bool
}

func (l *cappedListener) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		c, err := l.Listener.Accept(ctx)
		if err != nil {
			return nil, err
		}
		if l.draining.Load() || ctx.Err() != nil {
			// A server that stops accepting drops a connection handed to it
			// now, so it is turned away here instead.
			_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "shutting down")
			continue
		}
		if !l.e.sem.tryAcquire() {
			l.e.state.Failure(obs.ReasonMaxConnections)
			l.e.log.Warn("ingress.rejected", "reason", "max_connections", "protocol", "http3", "client_addr", c.RemoteAddr().String())
			_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "too many connections")
			continue
		}
		context.AfterFunc(c.Context(), l.e.sem.release)
		return c, nil
	}
}

// connActivity closes a QUIC connection that has no request in progress for
// too long: its first request must start within first, and after each
// request the next within idle. quic-go stops its own idle timer as soon as
// a stream opens, so without this a client could hold a connection (and its
// slot of the global cap) with a stream that never sends a request.
type connActivity struct {
	mu     sync.Mutex
	active int
	idle   time.Duration
	timer  *time.Timer
	gone   context.Context // done once the connection has closed
}

type connActivityKey struct{}

func newConnActivity(c *quic.Conn, first, idle time.Duration) *connActivity {
	a := &connActivity{idle: idle, gone: c.Context()}
	a.timer = time.AfterFunc(first, func() {
		// Decided and done under the lock, so a request that begins now
		// either finds the connection closed or keeps it open.
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.active == 0 {
			_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "idle")
		}
	})
	context.AfterFunc(c.Context(), func() { a.timer.Stop() })
	return a
}

// begin marks a request in progress; the returned func marks it done.
func (a *connActivity) begin() (end func()) {
	if a == nil {
		return func() {}
	}
	a.mu.Lock()
	a.active++
	a.timer.Stop()
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		if a.active--; a.active == 0 && a.gone.Err() == nil {
			a.timer.Reset(a.idle)
		}
		a.mu.Unlock()
	}
}

// routeSlot takes a slot of rs's connection cap for HTTP/3 request r,
// waiting up to wait (or until the client gives up) when the route is full.
// Over TCP a browser holds a few connections and queues its other requests;
// over HTTP/3 it sends them all at once, so they queue here instead, and the
// backend still sees at most the route's max_connections streams.
//
// A stream kept for some connection's next request holds a slot too; a
// request that finds the route full takes one from such a stream first, and
// while it waits, finished streams give theirs up instead of being kept.
func (e *Edge) routeSlot(r *http.Request, rs *routeState, wait time.Duration) bool {
	if rs.sem.tryAcquire() {
		return true
	}
	rs.slotWaiters.Add(1)
	defer rs.slotWaiters.Add(-1)
	if e.slotFromKept(rs) {
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	defer cancel()
	return rs.sem.acquire(ctx)
}

// slotFromKept takes a slot of rs's connection cap from a stream kept for
// some HTTP/3 connection's next request, if there is one: a request that
// needs the slot now comes first. Callers count themselves in
// rs.slotWaiters first, so that a stream finishing meanwhile is not kept.
func (e *Edge) slotFromKept(rs *routeState) bool {
	for e.h3pool.evictRoute(rs) {
		if rs.sem.tryAcquire() {
			return true
		}
	}
	return false
}

// peekWait bounds the look at a request body of unknown length (see
// serveHTTP3). A request without a body ends its stream with its headers, so
// the answer is normally there at once; a body that has not started by then
// is sent chunked, which works for any request.
const peekWait = 250 * time.Millisecond

// defaultHTTP3Idle closes an HTTP/3 connection with no requests when
// ingress.idle_timeout is not set (TCP connections then have no idle limit;
// a QUIC connection always needs one), and is the QUIC idle timeout that
// keep-alives hold off.
const defaultHTTP3Idle = 30 * time.Second

// serveHTTP3 handles one HTTP/3 request.
func (e *Edge) serveHTTP3(w http.ResponseWriter, r *http.Request) {
	connID := obs.NewID()
	log := e.log.With("conn_id", connID, "client_addr", r.RemoteAddr, "protocol", "http3")
	fail := func(code int, reason, detail string) {
		body := errpage.Render(code, reason, detail, connID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}

	// The body is never read once the handler returns: whatever reads it
	// stops when it is closed, and is waited for (see below).
	defer func() { _ = r.Body.Close() }()
	ca, _ := r.Context().Value(connActivityKey{}).(*connActivity)
	defer ca.begin()()
	ws := isWebSocketConnect(r)
	if r.Method == http.MethodConnect && !ws {
		log.Debug("ingress.connect_refused") // only WebSockets use CONNECT here
		fail(501, "Not Implemented", "CONNECT is not supported")
		return
	}

	host := route.Normalize(r.Host)
	var lines []byte
	var wsKey string
	var err error
	if ws {
		wsKey = newWebSocketKey()
		lines, err = webSocketHead(r, wsKey)
	} else {
		lines, err = http1Lines(r)
	}
	if err != nil {
		e.state.Failure(obs.ReasonBadRequest)
		log.Warn("ingress.bad_request", "error", err.Error())
		fail(400, "Bad Request", "Malformed request")
		return
	}
	log = log.With("host", host)
	rs, ok := e.routes.Match(host)
	if !ok {
		e.state.Failure(obs.ReasonNoRoute)
		log.Warn("ingress.no_route")
		fail(404, "Not Found", "No route for host")
		return
	}
	if rs.noHTTP3 {
		// The connection was made for another host (a browser may reuse one
		// for every host its certificate covers). 421 tells the client to
		// retry on a new connection, whose handshake is refused (see
		// refuseNoHTTP3), so it falls back to TCP.
		rs.stats.Failure(obs.ReasonHTTP3Off)
		log.Debug("ingress.http3_misdirected")
		fail(421, "Misdirected Request", "Not served over HTTP/3")
		return
	}
	trailers := trailerNames(r.Trailer)
	if !ws && r.ContentLength < 0 && len(trailers) == 0 && !expectsContinue(r) {
		// HTTP/3 does not say up front whether a request without
		// Content-Length has a body. Look before choosing the framing, so a
		// plain GET is not sent chunked.
		pb := peekBody(r.Body, peekWait)
		defer func() { _ = pb.Close(); <-pb.first }() // its read-ahead has ended
		if pb.done() && pb.err != nil && !errors.Is(pb.err, io.EOF) {
			// The request stream failed: reset it rather than answer an
			// empty 200.
			log.Debug("ingress.body_error", "error", pb.err.Error())
			panic(http.ErrAbortHandler)
		}
		r.Body, r.ContentLength = pb, pb.length()
	}
	head := lines // a WebSocket upgrade has no body
	if ws {
		ts := e.openH3Stream(r, rs, connID, host, head, log, fail)
		if ts == nil {
			return
		}
		defer ts.close() // an upgraded stream is never kept
		rs.stats.HTTP3Request()
		// A client that resets its request ends the stream at once, and with
		// it the backend's connection, as closing a TCP connection does.
		defer context.AfterFunc(r.Context(), func() { abort(ts.s) })()
		sb := rs.stats.Bytes()
		sb.AddIn(int64(len(head))) // sent with the preamble (v2) or after it
		tunnelSide := &countingConn{Conn: proxy.NewIdleConn(ts.s, e.cfg.Ingress.IdleTimeout.Duration()), in: sb.AddIn, out: sb.AddOut}
		e.serveHTTP3WebSocket(w, r, tunnelSide, int64(len(head)), wsKey, log, fail, rs.stats.Failure)
		return
	}
	head = framed(lines, r, trailers)
	// A small body is held in memory. An idempotent request with no body, or
	// one held, can be sent again; only such a request takes a kept stream,
	// which may turn out to have closed just as the request went out (see
	// h3Exchange). Others go on a fresh stream, which is then kept like any
	// other.
	held, inMemory, err := e.holdBody(w, r, trailers)
	if err != nil {
		// The body broke off, came short, or stalled for idle_timeout.
		log.Debug("ingress.body_error", "error", err.Error())
		panic(http.ErrAbortHandler)
	}
	cs := connStreamsOf(r)
	reuse := inMemory && idempotent(r) && cs != nil
	for sent := false; ; sent = true {
		var ts *tunnelStream
		if reuse {
			ts = e.h3pool.take(cs, host, rs)
		}
		reused := ts != nil
		if !reused {
			if ts = e.openH3Stream(r, rs, connID, host, head, log, fail); ts == nil {
				return
			}
		}
		if !sent {
			rs.stats.HTTP3Request() // once, however many streams it takes
		}
		if inMemory {
			r.Body = io.NopCloser(bytes.NewReader(held))
		}
		if !e.h3Exchange(w, r, cs, ts, head, reused, inMemory, trailers, log, fail) {
			return
		}
		reuse = false // sent again on a fresh stream
	}
}

// openH3Stream opens a tunnel stream for HTTP/3 request r to host on rs,
// whose HTTP/1.1 head is head, and sends the head. Otherwise it has answered
// the client, or given up on it, and returns nil.
func (e *Edge) openH3Stream(r *http.Request, rs *routeState, connID, host string, head []byte, log *slog.Logger, fail func(int, string, string)) *tunnelStream {
	if !e.routeSlot(r, rs, readHeaderDeadline(e.cfg.Ingress.ReadHeaderTimeout.Duration())) {
		if r.Context().Err() != nil {
			panic(http.ErrAbortHandler) // the client gave up waiting
		}
		rs.stats.Failure(obs.ReasonRouteMaxConnections)
		log.Warn("ingress.rejected", "reason", "route_max_connections")
		fail(503, "Service Unavailable", "Too many connections")
		return nil
	}
	stream, chosen, refused := e.dispatch(rs, connID, r.RemoteAddr, host, head, log)
	if refused != nil {
		rs.sem.release()
		fail(refused.code, refused.reason, refused.detail)
		return nil
	}
	if !chosen.v2 { // a version 1 agent gets the head after the preamble
		if _, err := stream.Write(head); err != nil {
			_ = stream.Close()
			chosen.stat.StreamClosed() // release the reservation: no stream after all
			rs.sem.release()
			rs.stats.Failure(obs.ReasonStreamError)
			log.Warn("stream.send_error", "agent_fp", chosen.fp, "error", err.Error())
			fail(streamFailed.code, streamFailed.reason, streamFailed.detail)
			return nil
		}
	}
	chosen.stat.Commit()
	e.state.StreamOpenedHTTP3(rs.stats)
	log.Debug("stream.open", "agent_fp", chosen.fp)
	return &tunnelStream{e: e, s: stream, agent: chosen, rs: rs, host: host}
}

// h3Exchange sends HTTP/3 request r on ts (its head, unless ts was just
// opened with it, and its body) and relays the response. After a clean
// exchange ts is kept in cs's pool for the connection's next request;
// otherwise it is closed.
//
// A kept stream (reused) can have closed just as the request went out: the
// service may end an idle connection at any time. When nothing came back,
// h3Exchange reports retry without answering, and the caller sends the
// request again on a fresh stream, as a browser resends a request on a
// keep-alive connection that closed under it.
func (e *Edge) h3Exchange(w http.ResponseWriter, r *http.Request, cs *connStreams, ts *tunnelStream, head []byte, reused, inMemory bool, trailers []string, log *slog.Logger, fail func(int, string, string)) (retry bool) {
	rs, fp := ts.rs, ts.agent.fp
	sb := rs.stats.Bytes()
	tunnelSide := &countingConn{Conn: proxy.NewIdleConn(ts.s, e.cfg.Ingress.IdleTimeout.Duration()), in: sb.AddIn, out: sb.AddOut}
	if reused {
		log.Debug("stream.reuse", "agent_fp", fp)
		if _, err := tunnelSide.Write(head); err != nil {
			log.Debug("stream.stale", "agent_fp", fp, "error", err.Error())
			ts.close()
			return true // nothing reached the service
		}
	} else {
		sb.AddIn(int64(len(head))) // sent with the preamble (v2) or after it
	}
	// A client that resets its request ends the stream at once, and with it
	// the backend's connection, as closing a TCP connection does.
	stopAbort := context.AfterFunc(r.Context(), func() { abort(ts.s) })

	upload := make(chan struct{})
	var clientBodyFailed, uploadFailed atomic.Bool
	body := &readErrs{r: r.Body}
	if inMemory {
		// A body held in memory (if any) is smaller than the stream's
		// window, so it goes at once, before the response is read: the
		// stream is at a message boundary when the response ends.
		err := sendBody(tunnelSide, body, r, trailers)
		close(upload)
		if err != nil {
			if reused {
				log.Debug("stream.stale", "agent_fp", fp, "error", err.Error())
				stopAbort()
				ts.close()
				return true // the kept stream had closed: nothing came back
			}
			log.Debug("stream.body_error", "error", err.Error())
			uploadFailed.Store(true)
			abort(ts.s) // the read below fails: the tunnel stream broke
		}
	} else {
		// The body goes up while the response comes down: a backend may
		// answer before it has read all of it.
		go func() {
			defer close(upload)
			if err := sendBody(tunnelSide, body, r, trailers); err != nil {
				// The stream cannot carry the rest of the body: end it, or
				// the backend would wait for it forever. Whether that is the
				// client's doing (its body broke off, or came short of its
				// Content-Length) or the tunnel's decides how the request
				// ends (see below).
				log.Debug("stream.body_error", "error", err.Error())
				short := r.ContentLength > 0 && body.n < r.ContentLength && errors.Is(err, io.EOF)
				clientBodyFailed.Store(body.failed || short)
				uploadFailed.Store(true)
				abort(ts.s)
			}
		}()
	}
	uploadDone := func() bool {
		select {
		case <-upload:
			return true
		default:
			return false
		}
	}
	kept := false
	defer func() {
		stopAbort()
		if !kept {
			ts.close() // which also ends an upload still writing
		}
		_ = r.Body.Close()
		<-upload // the body must not be read once the handler returns
	}()

	limited := newHeadLimit(tunnelSide)
	br := bufio.NewReaderSize(limited, 16<<10)
	resp, err := readFinalResponse(br, r.Method, func(code int, h http.Header) {
		// 100 Continue (the client may be waiting for it to send its body),
		// 103 Early Hints and the like go to the client as they come. Each
		// head gets the whole limit.
		limited.reset()
		copyResponseHeader(w.Header(), h)
		w.WriteHeader(code)
		for k := range h {
			w.Header().Del(k)
		}
	})
	switch {
	case err == nil:
		limited.done() // the body may be any length
	case reused && tunnelSide.outTotal == 0 && isTunnelGone(err) && r.Context().Err() == nil:
		// The kept stream had closed: nothing came back, so the service
		// cannot have answered. Send the request again on a fresh stream.
		log.Debug("stream.stale", "agent_fp", fp, "error", err.Error())
		return true
	case r.Context().Err() != nil || clientBodyFailed.Load():
		// The client gave up, or its body broke off (closing the stream is
		// what ended the read): not a failure of the service.
		log.Debug("stream.client_gone", "error", err.Error())
		panic(http.ErrAbortHandler)
	case isTimeout(err) && !uploadDone() && body.waiting.Load():
		// Nothing moved for idle_timeout while the edge was waiting on the
		// client's body: the client stalled, not the service. (Had the
		// service stopped reading it, the edge would be waiting to write.)
		log.Debug("stream.body_stalled", "agent_fp", fp)
		panic(http.ErrAbortHandler)
	case isTimeout(err):
		// No response within ingress.idle_timeout. Over TCP the connection
		// would just be closed; here the client gets a clear answer.
		rs.stats.Failure(obs.ReasonResponseTimeout)
		log.Warn("stream.response_timeout", "agent_fp", fp, "idle_timeout", e.cfg.Ingress.IdleTimeout.Duration().String())
		fail(504, "Gateway Timeout", "No response from the service in time")
		return false
	case isTunnelGone(err):
		rs.stats.Failure(obs.ReasonStreamError) // the tunnel stream broke
		log.Warn("stream.broken", "agent_fp", fp, "error", err.Error())
		fail(502, "Bad Gateway", "Tunnel stream failed")
		return false
	default:
		rs.stats.Failure(obs.ReasonBadResponse)
		log.Warn("stream.bad_response", "agent_fp", fp, "error", err.Error())
		fail(502, "Bad Gateway", "Invalid response from the service")
		return false
	}
	copyResponseHeader(w.Header(), resp.Header)
	if _, ok := resp.Header["Content-Type"]; !ok {
		// The HTTP/3 writer would guess one; the service sent none, and a
		// guess can turn an upload into HTML.
		w.Header()["Content-Type"] = nil
	}
	w.WriteHeader(resp.StatusCode)
	if resp.ContentLength < 0 {
		// A streamed response: its status and headers go out now, not with
		// its first bytes (an event stream may send none for a while).
		_ = http.NewResponseController(w).Flush()
	}
	// Flush every read only for a response streamed without a length (server-
	// sent events, a progress feed); a sized one flows as the writer fills.
	if err := copyResponse(w, resp.Body, resp.ContentLength < 0, e.cfg.Ingress.IdleTimeout.Duration()); err != nil {
		// The status is out: all that is left is to cut the response short,
		// so the client does not take it for complete. (The stream is
		// closed, not drained: the body is not read on.)
		log.Debug("stream.response_cut", "error", err.Error())
		panic(http.ErrAbortHandler)
	}
	for k, vs := range resp.Trailer { // known once the body has ended
		if httpguts.ValidTrailerHeader(k) { // not framing or routing fields
			w.Header()[http.TrailerPrefix+k] = vs
		}
	}
	// The exchange is over and the stream at a message boundary: keep it,
	// unless the service is closing its connection (or its response could
	// only end that way), the body did not all go up, the service sent more
	// than its response, or the client has already reset the request.
	if cs != nil && !resp.Close && uploadDone() && !uploadFailed.Load() && br.Buffered() == 0 && stopAbort() {
		kept = true
		e.h3pool.put(cs, ts, e.h3Idle())
		log.Debug("stream.kept", "agent_fp", fp)
		return false
	}
	log.Debug("stream.closed")
	return false
}

// maxHeldBody is the largest request body held in memory: sent at once,
// so the stream is at a message boundary when the response ends, and
// available to send again (see h3Exchange).
const maxHeldBody = 64 << 10

// holdBody reads r's body into memory when it is small, of a known length,
// not announced with Expect: 100-continue and not followed by trailers, and
// reports whether it did; a request without a body always counts as held.
func (e *Edge) holdBody(w http.ResponseWriter, r *http.Request, trailers []string) ([]byte, bool, error) {
	switch {
	case len(trailers) > 0 || expectsContinue(r) || r.ContentLength < 0 || r.ContentLength > maxHeldBody:
		return nil, false, nil
	case r.ContentLength == 0:
		return nil, true, nil
	}
	// A client that stops sending must not hold the request: the read is
	// bounded as a connection without a request is (see h3Idle), and
	// without a bound the body is streamed, as one too large to hold is. (A
	// deadline may cut a frame short; the request then ends anyway.)
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(time.Now().Add(e.h3Idle())) != nil {
		return nil, false, nil
	}
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	b := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, b); err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// idempotent reports a request that may be sent twice: an idempotent method
// (RFC 9110, section 9.2.2), or one the client marked with an idempotency
// key, as Go's HTTP client does. The service can have acted on a request
// and then closed its connection without answering; repeating that is
// harmless only for these.
func idempotent(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	}
	return r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != ""
}

// h3Idle is how long an HTTP/3 connection may go without a request, and so
// how long a stream is kept for its next one.
func (e *Edge) h3Idle() time.Duration {
	if idle := e.cfg.Ingress.IdleTimeout.Duration(); idle > 0 {
		return idle
	}
	return defaultHTTP3Idle
}

// hopHeaders are the HTTP/1.1 connection-level headers, which do not cross
// from one hop to the next (RFC 9110, section 7.6.1).
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Te", "Trailer"}

// http1Lines validates r and renders its request line and end-to-end
// headers in HTTP/1.1 form, without the body framing (see framed).
func http1Lines(r *http.Request) ([]byte, error) {
	if !httpguts.ValidHostHeader(r.Host) || r.Host == "" {
		return nil, fmt.Errorf("invalid :authority %q", r.Host)
	}
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	if !httpguts.ValidHeaderFieldName(r.Method) || target == "" || strings.ContainsAny(target, " \r\n\t") {
		return nil, errors.New("invalid request line")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, target, r.Host)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Host" || ck == "Content-Length" || slices.Contains(hopHeaders, ck) {
			continue
		}
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid header name %q", k)
		}
		vs := r.Header[k]
		if ck == "Cookie" && len(vs) > 1 {
			vs = []string{strings.Join(vs, "; ")} // HTTP/1.1 allows one Cookie line
		}
		for _, v := range vs {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid value for header %q", k)
			}
			fmt.Fprintf(&b, "%s: %s\r\n", ck, v)
		}
	}
	return b.Bytes(), nil
}

// framed completes lines (from http1Lines) with r's body framing; trailers
// are the request trailers that cross (see trailerNames).
func framed(lines []byte, r *http.Request, trailers []string) []byte {
	b := bytes.NewBuffer(slices.Clip(lines))
	switch {
	case len(trailers) > 0:
		// Trailers follow the body, which only chunked framing allows.
		fmt.Fprintf(b, "Trailer: %s\r\nTransfer-Encoding: chunked\r\n", strings.Join(trailers, ", "))
	case r.ContentLength > 0:
		fmt.Fprintf(b, "Content-Length: %d\r\n", r.ContentLength)
	case r.ContentLength < 0:
		b.WriteString("Transfer-Encoding: chunked\r\n")
	case methodHasBody(r.Method):
		b.WriteString("Content-Length: 0\r\n")
	}
	b.WriteString("\r\n") // keep-alive: the stream may carry the connection's next request
	return b.Bytes()
}

// methodHasBody reports methods whose requests are expected to carry a body,
// so an empty one is sent with Content-Length: 0.
func methodHasBody(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch
}

// trailerNames returns the request trailers that may cross, sorted: valid
// field names that are allowed in trailers.
func trailerNames(t http.Header) []string {
	var names []string
	for k := range t {
		if httpguts.ValidHeaderFieldName(k) && httpguts.ValidTrailerHeader(k) {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	return names
}

// sendBody writes r's body, read from body, to w, framed as framed
// announced. Trailers are taken from r once the body has ended.
func sendBody(w io.Writer, body io.Reader, r *http.Request, trailers []string) error {
	switch {
	case len(trailers) > 0 || r.ContentLength < 0:
		// Each chunk (size line, data, CRLF) goes out as one write.
		bw := bufio.NewWriterSize(w, 32<<10+16)
		cw := httputil.NewChunkedWriter(bw)
		buf := make([]byte, 32<<10)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				if _, werr := cw.Write(buf[:n]); werr != nil {
					return werr
				}
				if werr := bw.Flush(); werr != nil {
					return werr
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		if err := cw.Close(); err != nil { // the last, empty chunk
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		var tb bytes.Buffer
		// Trailers are known once the body has ended, including any the
		// client sent without announcing them (HTTP/3 does not require it).
		for _, k := range trailerNames(r.Trailer) {
			for _, v := range r.Trailer[k] {
				if httpguts.ValidHeaderFieldValue(v) {
					fmt.Fprintf(&tb, "%s: %s\r\n", k, v)
				}
			}
		}
		tb.WriteString("\r\n")
		_, err := w.Write(tb.Bytes())
		return err
	case r.ContentLength > 0:
		_, err := io.CopyN(w, body, r.ContentLength)
		return err
	default:
		return nil
	}
}

// abort ends a tunnel stream at once. Closing a yamux stream only sends
// FIN, and reads already waiting on it would wait on, so they are woken too.
func abort(s net.Conn) {
	_ = s.SetDeadline(time.Now())
	_ = s.Close()
}

// readFinalResponse reads the backend's response, passing interim (1xx)
// ones to interim. A 101 is refused: the request asked for no protocol
// switch (see readUpgradeResponse for one that did).
func readFinalResponse(br *bufio.Reader, method string, interim func(code int, h http.Header)) (*http.Response, error) {
	return readResponse(br, method, false, interim)
}

// readUpgradeResponse is readFinalResponse for an upgrade request: a 101 is
// its final response, and interim ones are dropped.
func readUpgradeResponse(br *bufio.Reader, limited *headLimit) (*http.Response, error) {
	return readResponse(br, http.MethodGet, true, func(int, http.Header) { limited.reset() })
}

func readResponse(br *bufio.Reader, method string, upgrade bool, interim func(code int, h http.Header)) (*http.Response, error) {
	req := &http.Request{Method: method}
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode < 100:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("invalid status %d", resp.StatusCode)
		case resp.StatusCode == http.StatusSwitchingProtocols && upgrade:
			return resp, nil
		case resp.StatusCode == http.StatusSwitchingProtocols:
			_ = resp.Body.Close()
			return nil, errors.New("unexpected protocol switch")
		case resp.StatusCode >= 100 && resp.StatusCode < 200:
			_ = resp.Body.Close()
			interim(resp.StatusCode, resp.Header)
			continue
		}
		return resp, nil
	}
}

// expectsContinue reports a request whose client waits for 100 Continue
// before sending its body.
func expectsContinue(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Expect"), "100-continue")
}

// peekBody starts reading body and waits up to wait for the first read to
// return, to choose the framing (see length). The first read runs on its own
// goroutine rather than under a read deadline: a deadline could cut an
// HTTP/3 frame header in half. The returned body yields the whole body, the
// bytes read ahead first; closing it ends the read ahead, and the caller
// waits for first before returning.
func peekBody(body io.ReadCloser, wait time.Duration) *peekedBody {
	p := &peekedBody{ReadCloser: body, first: make(chan struct{})}
	go func() {
		defer close(p.first)
		buf := make([]byte, 512) // enough to tell empty from not
		n, err := body.Read(buf)
		p.buf, p.err = buf[:n], err
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-p.first:
	case <-t.C:
	}
	return p
}

// peekedBody is a request body whose first read was started ahead of time.
type peekedBody struct {
	io.ReadCloser
	first chan struct{} // closed once the first read has returned
	buf   []byte
	err   error
	taken bool
}

// done reports whether the first read has returned.
func (p *peekedBody) done() bool {
	select {
	case <-p.first:
		return true
	default:
		return false
	}
}

// length is the framing to use: the exact length when the whole body came in
// the first read (0 for none), -1 (chunked) otherwise.
func (p *peekedBody) length() int64 {
	if p.done() && errors.Is(p.err, io.EOF) {
		return int64(len(p.buf))
	}
	return -1
}

func (p *peekedBody) Read(b []byte) (int, error) {
	if !p.taken {
		<-p.first
		if len(p.buf) > 0 {
			n := copy(b, p.buf)
			p.buf = p.buf[n:]
			return n, nil
		}
		p.taken = true
		if p.err != nil {
			return 0, p.err
		}
	}
	return p.ReadCloser.Read(b)
}

// readErrs is a reader that remembers whether a read failed (other than at
// the end), to tell a client's broken body from a broken tunnel.
type readErrs struct {
	r       io.Reader
	n       int64 // bytes read
	failed  bool
	waiting atomic.Bool // a read is in progress: the edge waits on the client
}

func (e *readErrs) Read(b []byte) (int, error) {
	e.waiting.Store(true)
	n, err := e.r.Read(b)
	e.waiting.Store(false)
	e.n += int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		e.failed = true
	}
	return n, err
}

// headLimit bounds what a backend can send before its response head ends:
// reads fail once more than limit bytes have come, until done is called.
// The response head is parsed in full, so an endless head would otherwise
// be held in memory.
type headLimit struct {
	r     io.Reader
	left  int64
	freed bool
}

func newHeadLimit(r io.Reader) *headLimit {
	return &headLimit{r: r, left: headLimitBytes}
}

// headLimitBytes is a head, and what a buffered read takes beyond it.
const headLimitBytes = maxHeaderBytes + 32<<10

var errHeadTooLarge = errors.New("response head too large")

func (h *headLimit) Read(b []byte) (int, error) {
	if h.freed {
		return h.r.Read(b)
	}
	if h.left <= 0 {
		return 0, errHeadTooLarge
	}
	if int64(len(b)) > h.left {
		b = b[:h.left]
	}
	n, err := h.r.Read(b)
	h.left -= int64(n)
	return n, err
}

// done lifts the limit once the head has been read.
func (h *headLimit) done() { h.freed = true }

// reset starts the limit over for the next head (after an interim one).
func (h *headLimit) reset() { h.left = headLimitBytes }

// isTunnelGone reports an error from the tunnel stream itself ending (closed,
// reset, cut short), as opposed to the service sending something invalid.
func isTunnelGone(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || tunnel.IsTeardown(err)
}

// isTimeout reports a read that hit its deadline (a yamux stream reports
// its own timeout error, a QUIC stream os.ErrDeadlineExceeded).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

// copyResponseHeader copies an HTTP/1.1 response's end-to-end headers.
func copyResponseHeader(dst, src http.Header) {
	var drop map[string]bool
	for _, v := range src.Values("Connection") {
		if drop == nil {
			drop = map[string]bool{}
		}
		for _, t := range strings.Split(v, ",") {
			drop[http.CanonicalHeaderKey(strings.TrimSpace(t))] = true
		}
	}
	for k, vs := range src {
		if drop[k] || slices.Contains(hopHeaders, k) {
			continue
		}
		dst[k] = append(dst[k], vs...)
	}
}

// copyResponse copies src to w; with flush, it flushes after every read so a
// streamed response reaches the client at once. With idle > 0 each write
// must finish within idle, as on the TCP ingress: a client that stops
// reading does not hold its stream (and route slot) forever.
func copyResponse(w http.ResponseWriter, src io.Reader, flush bool, idle time.Duration) error {
	rc := http.NewResponseController(w)
	bp := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if idle > 0 {
				_ = rc.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flush {
				_ = rc.Flush()
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

var copyBufs = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// countingConn reports the bytes written to and read from a tunnel stream,
// and keeps their totals (read them once its users are done).
type countingConn struct {
	net.Conn
	in, out           func(int64)
	inTotal, outTotal int64
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.inTotal += int64(n)
	c.in(int64(n))
	return n, err
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.outTotal += int64(n)
	c.out(int64(n))
	return n, err
}

// serveHTTP3Until runs srv on pc until ctx ends, then shuts it down within
// the drain budget, letting requests in flight finish. done is closed when it
// has stopped.
func (e *Edge) serveHTTP3Until(ctx context.Context, srv *http3.Server, tr *quic.Transport, ln *cappedListener, pc net.PacketConn, done chan<- struct{}) {
	defer close(done)
	defer func() { _ = tr.Close() }()
	defer func() { _ = ln.Close() }()
	served := make(chan error, 1)
	go func() { served <- srv.ServeListener(ln) }()
	select {
	case err := <-served:
		// HTTP/3 is gone while TCP carries on: stop sending browsers to it,
		// and release the port so their QUIC attempts fail at once.
		e.altSvc.Store("")
		e.state.SetHTTP3Listen("")
		_ = pc.Close()
		e.log.Error("http3.serve", "error", err.Error())
		return
	case <-ctx.Done():
	}
	// Draining: the server stops accepting, so turn new connections away
	// here, at once, rather than leave them queued until their handshake
	// times out. Established ones finish their requests.
	ln.draining.Store(true)
	go func() { _, _ = ln.Accept(context.Background()) }() // returns when ln closes
	e.h3pool.closeAll()                                    // requests in flight finish; their streams are not kept
	sctx, cancel := context.WithTimeout(context.Background(), e.cfg.Drain.Duration())
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		e.log.Warn("http3.drain_timeout", "error", err.Error())
	}
	_ = srv.Close()
	<-served
}
