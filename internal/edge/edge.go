package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/errpage"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// routeState is the per-route value stored in the matcher: the agent
// fingerprint(s) that serve it, how to balance across their sessions, an
// optional per-route connection cap, and the route's counters (nil-safe, so a
// routeState built without stats still works).
type routeState struct {
	fingerprints []string // the agents that serve the route
	label        string   // fingerprints joined, for logs
	balance      string   // config.BalanceLeastConn (default) or config.BalanceRoundRobin
	rr           atomic.Uint64
	pickMu       *sync.Mutex // the edge's pick lock (see pickReserve); nil in tests
	sem          *semaphore
	stats        *obs.RouteStats
}

// pick chooses a session among cands, skipping those already tried for this
// request (pick adds its choice to tried). turn is the
// request's position in the route's rotation (see nextTurn); a request reuses
// it for its retries, so retries do not advance the rotation. Sessions cooling
// down after a failure are used only if nothing else is left. round_robin
// takes the turn-th of the remaining sessions, so a skipped session's turns
// spread evenly over the others; least_conn takes the one with the fewest open
// streams, starting its scan at the turn so ties spread evenly. It returns nil
// when every candidate has been tried.
func (rs *routeState) pick(cands []*agentConn, tried map[*agentConn]bool, turn uint64) *agentConn {
	n := len(cands)
	if n == 0 {
		return nil
	}
	now := time.Now().UnixNano()
	idx := -1
	for pass := 0; pass < 2 && idx < 0; pass++ {
		eligible := func(i int) bool { return !tried[cands[i]] && (pass == 1 || cands[i].coolUntil.Load() <= now) }
		if rs.balance == config.BalanceRoundRobin {
			count := 0
			for i := range cands {
				if eligible(i) {
					count++
				}
			}
			if count == 0 {
				continue
			}
			k := int(turn % uint64(count))
			for i := range cands {
				if eligible(i) {
					if k == 0 {
						idx = i
						break
					}
					k--
				}
			}
			continue
		}
		start := int(turn % uint64(n))
		for j := 0; j < n; j++ {
			i := (start + j) % n
			if eligible(i) && (idx < 0 || cands[i].stat.Active() < cands[idx].stat.Active()) {
				idx = i
			}
		}
	}
	if idx < 0 {
		return nil
	}
	tried[cands[idx]] = true
	return cands[idx]
}

// pickReserve is pick plus counting the new stream on the chosen session, as
// one step, so concurrent least_conn picks see each other's choices (a burst
// spreads instead of landing on one agent). The caller must release the
// reservation (StreamClosed) if the stream cannot be set up.
func (rs *routeState) pickReserve(cands []*agentConn, tried map[*agentConn]bool, turn uint64) *agentConn {
	// least_conn reads per-session counts that routes sharing agents also
	// use, so choosing and reserving is one step under the edge-wide lock.
	// round_robin and single-candidate routes need no lock.
	if rs.pickMu != nil && len(cands) > 1 && rs.balance != config.BalanceRoundRobin {
		rs.pickMu.Lock()
		defer rs.pickMu.Unlock()
	}
	c := rs.pick(cands, tried, turn)
	if c != nil {
		c.stat.Reserve()
	}
	return c
}

// nextTurn advances the route's rotation and returns the request's turn.
// The first request gets turn 0, so a rotation starts at the first session.
func (rs *routeState) nextTurn() uint64 { return rs.rr.Add(1) - 1 }

// cooldown keeps a session that failed to set up a stream (while staying
// open) out of picks for a moment, so least_conn does not keep preferring it.
const cooldown = time.Second

type Edge struct {
	cfg     *config.EdgeConfig
	log     *slog.Logger
	state   *obs.State
	tunTLS  *tls.Config
	allowed map[string]bool
	reg     *registry
	routes  *route.Matcher[*routeState]
	sem     *semaphore // global ingress connection cap
	pickMu  sync.Mutex // shared by all routes' least_conn picks
	drainWG sync.WaitGroup
	altSvc  atomic.Value // string: Alt-Svc value added to TCP responses ("" for none)
	pubCert struct {
		once sync.Once
		cert tls.Certificate
		err  error
	}
}

// publicCert loads the ingress certificate (standalone mode) once, so TCP
// and HTTP/3 serve the same one.
func (e *Edge) publicCert() (tls.Certificate, error) {
	e.pubCert.once.Do(func() {
		e.pubCert.cert, e.pubCert.err = tls.LoadX509KeyPair(e.cfg.Ingress.TLS.Cert, e.cfg.Ingress.TLS.Key)
		if e.pubCert.err != nil {
			e.pubCert.err = fmt.Errorf("load public cert: %w", e.pubCert.err)
		}
	})
	return e.pubCert.cert, e.pubCert.err
}

func New(cfg *config.EdgeConfig, log *slog.Logger, state *obs.State) (*Edge, error) {
	pool, cert, err := tunnel.LoadMaterial(cfg.Tunnel.CA, cfg.Tunnel.Cert, cfg.Tunnel.Key, "edge cert")
	if err != nil {
		return nil, err
	}
	if cert.Leaf != nil {
		state.SetSelfFingerprint(pki.Fingerprint(cert.Leaf))
	}
	e := &Edge{cfg: cfg, log: log, state: state, tunTLS: tunnel.ServerTLSConfig(pool, cert), allowed: cfg.AllowedFingerprints(), reg: newRegistry(), sem: newSemaphore(cfg.Ingress.MaxConnections)}
	e.reg.shared = cfg.SharedFingerprints()
	e.altSvc.Store("") // set once HTTP/3 is up (see ServeWithHTTP3)
	state.ExpectAgents(e.allowed)
	entries := make([]route.Entry[*routeState], 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		fps := r.Fingerprints()
		rs := &routeState{fingerprints: fps, label: strings.Join(fps, ","), balance: r.BalanceMode(), pickMu: &e.pickMu, sem: newSemaphore(r.MaxConnections), stats: state.Route(route.Normalize(r.Host))}
		entries = append(entries, route.Entry[*routeState]{Pattern: r.Host, Value: rs})
	}
	e.routes = route.Build(entries)
	return e, nil
}

func (e *Edge) Run(ctx context.Context) error {
	tunLn, err := tls.Listen("tcp", e.cfg.Tunnel.Listen, e.tunTLS)
	if err != nil {
		return fmt.Errorf("tunnel listen: %w", err)
	}
	ingressLn, err := e.listenIngress()
	if err != nil {
		_ = tunLn.Close()
		return err
	}
	var h3 net.PacketConn
	if e.cfg.Ingress.HTTP3.Enabled {
		if h3, err = net.ListenPacket("udp", e.cfg.Ingress.HTTP3Listen()); err != nil {
			_ = tunLn.Close()
			_ = ingressLn.Close()
			return fmt.Errorf("http3 listen: %w", err)
		}
	}
	return e.ServeWithHTTP3(ctx, tunLn, ingressLn, h3)
}

func (e *Edge) listenIngress() (net.Listener, error) {
	switch e.cfg.Ingress.Mode {
	case "standalone":
		cert, err := e.publicCert()
		if err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", e.cfg.Ingress.Listen)
		if err != nil {
			return nil, err
		}
		// wireListener lets handleIngress tell an empty connection from an
		// abandoned TLS handshake (see closedWithoutRequest).
		return tls.NewListener(wireListener{ln}, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	case "proxied":
		return net.Listen("tcp", e.cfg.Ingress.Listen)
	default:
		return nil, fmt.Errorf("unknown ingress mode %q", e.cfg.Ingress.Mode)
	}
}

// Serve runs the accept loops on the given listeners until ctx is cancelled.
func (e *Edge) Serve(ctx context.Context, tunLn, ingressLn net.Listener) error {
	return e.ServeWithHTTP3(ctx, tunLn, ingressLn, nil)
}

// ServeWithHTTP3 is Serve that also serves HTTP/3 on h3 when it is not nil.
// It closes h3 when it returns.
func (e *Edge) ServeWithHTTP3(ctx context.Context, tunLn, ingressLn net.Listener, h3 net.PacketConn) error {
	e.log.Info("tunnel.listen", "address", tunLn.Addr().String())
	e.log.Info("ingress.listen", "mode", e.cfg.Ingress.Mode, "address", ingressLn.Addr().String())
	h3Done := make(chan struct{})
	if h3 != nil {
		defer func() { _ = h3.Close() }()
		srv, tr, ln, err := e.startHTTP3(h3)
		if err != nil {
			_ = tunLn.Close()
			_ = ingressLn.Close()
			return err
		}
		// Advertise it only now that it is served, on the port it is served on.
		port := 0
		if ua, ok := h3.LocalAddr().(*net.UDPAddr); ok {
			port = ua.Port
		}
		e.altSvc.Store(e.cfg.Ingress.AltSvcHeaderFor(port))
		e.log.Info("ingress.listen", "protocol", "http3", "address", h3.LocalAddr().String(), "alt_svc", e.altSvc.Load())
		go e.serveHTTP3Until(ctx, srv, tr, ln, h3, h3Done)
	} else {
		close(h3Done)
	}
	go func() {
		<-ctx.Done()
		_ = tunLn.Close()
		_ = ingressLn.Close()
	}()
	go e.acceptTunnel(ctx, tunLn)
	e.acceptIngress(ctx, ingressLn) // returns once ingressLn is closed
	budget := time.Now().Add(e.cfg.Drain.Duration())
	e.drain() // no new handlers can start now
	// HTTP/3 requests drain in parallel, within the same budget. Once it is
	// spent, the agent sessions are closed, which also ends HTTP/3 requests
	// still waiting on a tunnel (as it ends TCP ones).
	select {
	case <-h3Done:
	case <-time.After(time.Until(budget)):
	}
	e.reg.closeAll()
	<-h3Done
	return nil
}

// startHTTP3 sets up HTTP/3 on h3 with the ingress certificate.
func (e *Edge) startHTTP3(h3 net.PacketConn) (*http3.Server, *quic.Transport, *cappedListener, error) {
	cert, err := e.publicCert()
	if err != nil {
		return nil, nil, nil, err
	}
	srv, tr, ln, err := e.newHTTP3(cert, h3)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("http3 listen: %w", err)
	}
	e.state.SetHTTP3Listen(h3.LocalAddr().String())
	return srv, tr, ln, nil
}

// drain waits up to cfg.Drain for in-flight ingress handlers to finish.
func (e *Edge) drain() {
	obs.DrainWait(e.log, &e.drainWG, e.cfg.Drain.Duration())
}

// acceptRetryDelay bounds how long an accept loop pauses after a transient
// Accept error before retrying, so a momentary failure (for example fd
// exhaustion) neither permanently stops the listener nor spins hot.
var acceptRetryDelay = 100 * time.Millisecond

// acceptLoop accepts connections until ctx is cancelled, dispatching each to
// handle. A cancelled ctx ends the loop quietly; any other Accept error is
// logged and retried after acceptRetryDelay rather than silently ending it.
func (e *Edge) acceptLoop(ctx context.Context, ln net.Listener, name string, handle func(net.Conn)) {
	for ctx.Err() == nil {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Warn("accept.error", "listener", name, "error", err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(acceptRetryDelay):
			}
			continue
		}
		handle(conn)
	}
}

func (e *Edge) acceptTunnel(ctx context.Context, ln net.Listener) {
	e.acceptLoop(ctx, ln, "tunnel", func(conn net.Conn) { go e.serveAgent(conn) })
}

// handshakeTimeout bounds the TLS handshake on the internet-facing tunnel
// listener so an unauthenticated peer cannot pin a goroutine/fd indefinitely.
const handshakeTimeout = 10 * time.Second

// defaultReadHeaderTimeout is the read/handshake deadline applied to public
// ingress connections when the configured value is non-positive. The deadline
// is always enforced, so slow-loris protection on the public listener cannot be
// switched off by configuration.
const defaultReadHeaderTimeout = 10 * time.Second

func readHeaderDeadline(configured time.Duration) time.Duration {
	if configured <= 0 {
		return defaultReadHeaderTimeout
	}
	return configured
}

func (e *Edge) serveAgent(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		if tunnel.IsTeardown(err) {
			// The peer went away before completing the TLS handshake: a health
			// check, load-balancer probe, port scan, or doctor's reachability
			// probe. Not a real failure, so don't count it or warn.
			e.log.Debug("agent.tls_handshake", "verify_result", "incomplete", "error", err.Error())
		} else {
			// The peer attempted TLS but never authenticated (no client
			// certificate, or an incompatible TLS version or cipher). On a public
			// mTLS port this is routine scanner/probe noise: counted as rejected,
			// not as a failure, and logged at info with its source address.
			e.state.HandshakeRejected()
			e.log.Info("agent.tls_handshake", "verify_result", "rejected", "remote_addr", conn.RemoteAddr().String(), "error", err.Error())
		}
		_ = conn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	fp := pki.Fingerprint(tlsConn.ConnectionState().PeerCertificates[0])
	if len(e.allowed) > 0 && !e.allowed[fp] {
		e.state.HandshakeFail()
		e.log.Warn("agent.tls_handshake", "verify_result", "fingerprint_not_allowed", "peer_fp", fp)
		_ = conn.Close()
		return
	}
	session, err := tunnel.ServerSession(tlsConn)
	if err != nil {
		_ = conn.Close()
		return
	}
	switch e.reg.track(fp, session) {
	case trackClosing:
		_ = session.Close() // the edge is shutting down
		return
	case trackCapped:
		e.state.HandshakeCapped()
		e.log.Warn("agent.too_many_sessions", "peer_fp", fp, "remote_addr", tlsConn.RemoteAddr().String(), "limit", maxSharedSessions, "phase", "connecting")
		_ = session.Close()
		return
	}
	defer e.reg.drop(session)
	// Refuse an obvious duplicate before the ping below, so a cloned
	// certificate cannot hold connections open while it is checked.
	probed := false // a newcomer probes the incumbents for GoAway at most once
	if e.reg.hasLiveExclusive(fp) {
		probed = true
		if e.duplicateAfterProbe(fp) {
			e.refuseDuplicate(fp, session)
			return
		}
	}
	// Require a working yamux peer before offering the session traffic: a
	// `coen doctor` handshake probe completes TLS and closes before it can
	// answer a ping, so it never joins the pool. (A probe whose exclusive
	// certificate already has a live agent was refused as a duplicate above.)
	if _, err := session.Ping(); err != nil {
		// A probe hangs up right after TLS (the session shuts down): routine.
		// Anything else, such as a ping timeout, is a real agent that could
		// not be brought into service; say so at the default log level.
		if errors.Is(err, yamux.ErrSessionShutdown) || session.IsClosed() {
			e.log.Debug("agent.not_ready", "peer_fp", fp, "error", err.Error())
		} else {
			e.state.HandshakeFail()
			e.log.Warn("agent.not_ready", "peer_fp", fp, "remote_addr", tlsConn.RemoteAddr().String(), "error", err.Error())
		}
		_ = session.Close()
		return
	}
	addr := tlsConn.RemoteAddr().String()
	c := &agentConn{fp: fp, sess: session, stat: e.state.NewAgentSession(fp, addr), v2: tlsConn.ConnectionState().NegotiatedProtocol == tunnel.ALPNv2}
	// List the session before pooling it: once pooled a request may pick
	// and evict it at once, and an eviction unlists it.
	e.state.AddAgent(c.stat)
	result, pooled := e.reg.registerConn(fp, c)
	if result == refusedDuplicate && !probed && !e.duplicateAfterProbe(fp) {
		result, pooled = e.reg.registerConn(fp, c)
	}
	if result != registered {
		e.state.AgentDisconnected(c.stat)
	}
	switch result {
	case registered:
	case refusedGone:
		_ = session.Close() // shutting down, or the agent already went away
		return
	case refusedCap:
		e.state.HandshakeCapped()
		e.log.Warn("agent.too_many_sessions", "peer_fp", fp, "remote_addr", addr, "limit", maxSharedSessions)
		_ = session.Close()
		return
	case refusedDuplicate:
		e.refuseDuplicate(fp, session)
		return
	}
	e.state.HandshakeOK() // count only a fully accepted agent, not a refused duplicate
	if pooled > 1 {
		// Another agent joined a shared certificate. Expected when scaling
		// out; unexpected joins may mean the certificate has leaked.
		e.log.Info("agent.connected", "peer_fp", fp, "remote_addr", addr, "shared_sessions", pooled)
	} else {
		e.log.Info("agent.connected", "peer_fp", fp, "remote_addr", addr)
	}
	if c.v2 {
		// The agent asks to be retired over a control stream when it shuts
		// down (a version 2 feature, negotiated in the TLS handshake).
		go tunnel.ServeControl(session, func() { e.retireForDrain(c) })
	}

	// This goroutine owns the session's lifetime: whoever closes it (the
	// agent, an eviction, or shutdown), the disconnect is recorded once, here.
	<-session.CloseChan()
	e.state.AgentDisconnected(c.stat)
	e.log.Info("agent.disconnected", "peer_fp", fp)
}

// retireGoingAway retires fp's pooled sessions whose agent has sent GoAway. An agent sends GoAway when it stops;
// normally its drain request has already taken it out of the pool, but if
// that request was lost the edge would otherwise notice only on its next
// pick of it, and on a quiet route a replacement with the same certificate
// would be refused as a duplicate meanwhile. yamux exposes GoAway only
// through a failing open, so each session is probed with one: on a session
// that is not going away the probe stream is closed at once, empty, which an
// agent ignores. It runs only when a newcomer would be refused.
func (e *Edge) retireGoingAway(fp string) {
	live, _ := e.reg.candidates([]string{fp})
	for _, c := range live {
		if !c.v2 {
			continue // an older agent never sends GoAway, and would log the probe
		}
		s, err := openUnlessRetired(c, probeWait)
		switch {
		case errors.Is(err, yamux.ErrRemoteGoAway):
			e.retire(c)
		case err == nil:
			_ = s.Close()
		}
	}
}

// duplicateAfterProbe is the duplicate rule for a newcomer of fp that would
// be refused: a session whose agent is going away does not count, so it
// retires those first and reports whether fp still has a live session.
func (e *Edge) duplicateAfterProbe(fp string) bool {
	e.retireGoingAway(fp)
	// Asked again in any case: the incumbent may also have closed, or been
	// retired by its own drain request, while it was probed.
	return e.reg.hasLiveExclusive(fp)
}

// probeWait bounds retireGoingAway's open on each session.
const probeWait = time.Second

// refuseDuplicate drops a second connection with a certificate that already
// has a live session and is not shared, so a duplicate certificate (or a stray
// reconnect) cannot disrupt the serving agent. It is not counted as a
// successful handshake.
func (e *Edge) refuseDuplicate(fp string, session *yamux.Session) {
	e.state.HandshakeDuplicate()
	e.log.Warn("agent.duplicate_fingerprint", "peer_fp", fp)
	_ = session.Close()
}

// evict removes a dead session from the pool and closes it, so a reconnecting
// agent can register at once instead of being refused as a duplicate while
// requests fail until the tunnel keepalive fires. take is session-guarded, so
// a concurrent reconnect is safe. Status and metrics stop listing it at once
// (its serveAgent goroutine records the disconnect again, harmlessly, when
// the close lands).
//
// The close runs in the background: on a stalled connection it can block for
// the TLS write timeout, and the session is already out of the pool. A
// session already closed needs none.
func (e *Edge) evict(c *agentConn) {
	e.reg.take(c.fp, c.sess)
	e.state.AgentDisconnected(c.stat)
	if !c.sess.IsClosed() {
		go func() { _ = c.sess.Close() }()
	}
}

// attempt is the outcome of trying to hand a request to one agent session.
type attempt int

const (
	attemptOK          attempt = iota // the agent has the stream (and, version 2, the head)
	attemptUnavailable                // draining or refusing: nothing reached it, try another
	attemptFailed                     // the session failed before the request reached it, try another
	attemptUnknown                    // the agent may have the request: do not retry
)

// tryAgent opens a stream on c (already reserved by pickReserve) and sends the
// preamble; with a version 2 agent it waits for the agent to accept, then
// sends the preamble and the request head. On every outcome but attemptOK it
// has released the reservation, closed the stream, and retired, evicted, or
// cooled down the session, as each failure below decides.
//
// wait bounds the whole attempt: the stream open and, for a version 2 agent,
// the wait for its accept byte together.
func (e *Edge) tryAgent(c *agentConn, preamble, head []byte, wait time.Duration) (s net.Conn, outcome attempt, err error) {
	end := time.Now().Add(wait)
	retire := func() { e.retire(c) }          // shutting down gracefully: in-flight streams finish
	evict := func() { e.evict(c) }            // unusable: close it, so the agent reconnects
	coolFor := func(d time.Duration) func() { // steer the next requests elsewhere for d
		return func() { c.coolDownFor(d) }
	}
	// A healthy agent answers within a round trip, so one that stayed silent
	// for at least half of acceptWait is stalled: keep it out until the
	// tunnel keepalive has judged it. A shorter window (cut by the request's
	// deadline, or by a slow open before it) says nothing about the agent.
	stalledAfter := func(silent time.Duration) func() {
		if silent >= acceptWait/2 {
			return coolFor(2 * acceptWait)
		}
		return func() {}
	}
	fail := func(o attempt, then func(), err error) (net.Conn, attempt, error) {
		c.stat.StreamClosed()
		if s != nil {
			_ = s.Close()
		}
		then()
		return nil, o, err
	}
	// gone reports a failure caused by the session having closed: the agent
	// is no longer there, which counts as unavailable, not as a stream error.
	gone := func() bool { return c.sess.IsClosed() }

	st, err := openUnlessRetired(c, wait)
	switch {
	case errors.Is(err, errRetired) || errors.Is(err, yamux.ErrRemoteGoAway):
		return fail(attemptUnavailable, retire, err)
	case err != nil && gone():
		return fail(attemptUnavailable, evict, err)
	case errors.Is(err, errOpenTimeout):
		return fail(attemptFailed, func() {}, err) // openUnlessRetired marked it stalled
	case errors.Is(err, errOpenBlocked):
		// Still stalled (an earlier open has not returned): keep it marked
		// in case that mark has run out meanwhile.
		return fail(attemptFailed, coolFor(2*acceptWait), err)
	case err != nil:
		return fail(attemptFailed, evict, err) // streams exhausted, a write timeout
	}
	s = st
	if !c.v2 {
		// Version 1: the preamble goes now and the head through the pipe. A
		// preamble alone cannot run a request, so a failed write is safe to
		// retry; a reset stream on a live session is the agent refusing it.
		if _, err := s.Write(preamble); err != nil {
			switch {
			case gone():
				return fail(attemptUnavailable, evict, err)
			case streamRefused(err):
				return fail(attemptUnavailable, coolFor(cooldown), err)
			}
			return fail(attemptFailed, coolFor(cooldown), err)
		}
		return s, attemptOK, nil
	}
	// Version 2: the agent accepts a stream on arrival, before reading it, so
	// nothing is sent until it has. Until then any failure (a refusal, a
	// timeout, a dead session) is safe to retry elsewhere, and an agent that
	// accepts late finds an empty stream: no request, no backend dial.
	window := time.Until(end)
	if err := tunnel.AwaitAccept(s, window); err != nil {
		switch {
		case gone():
			return fail(attemptUnavailable, evict, err)
		case errors.Is(err, tunnel.ErrRefused):
			return fail(attemptUnavailable, coolFor(cooldown), err) // draining, or a full accept queue
		case errors.Is(err, tunnel.ErrBadAccept):
			return fail(attemptFailed, evict, err) // a protocol fault: drop the session
		}
		return fail(attemptFailed, stalledAfter(window), err) // no answer in time
	}
	// The agent has the stream. Once the request goes out it may run it, so
	// a failure from here on is never retried.
	if _, err := s.Write(append(preamble, head...)); err != nil {
		if gone() {
			return fail(attemptUnknown, evict, err)
		}
		return fail(attemptUnknown, coolFor(cooldown), err)
	}
	return s, attemptOK, nil
}

// streamRefused reports a write error from a stream the agent reset or closed.
func streamRefused(err error) bool {
	return errors.Is(err, yamux.ErrConnectionReset) || errors.Is(err, yamux.ErrStreamClosed)
}

// untried returns rs's live sessions not in attempted. Closed sessions not
// yet removed by their serveAgent goroutine are evicted now, so a
// reconnecting agent is not refused meanwhile.
func (e *Edge) untried(rs *routeState, attempted map[*agentConn]bool) []*agentConn {
	live, dead := e.reg.candidates(rs.fingerprints)
	for _, c := range dead {
		e.evict(c)
	}
	if len(attempted) == 0 {
		return live
	}
	fresh := live[:0:0]
	for _, c := range live {
		if !attempted[c] {
			fresh = append(fresh, c)
		}
	}
	return fresh
}

// errRetired reports a pick of a session that was retired meanwhile.
var errRetired = errors.New("agent session retired")

// errOpenTimeout reports a stream open that did not finish within its wait.
var errOpenTimeout = errors.New("stream open timed out")

// errOpenBlocked reports an open not tried because an earlier one on the
// session is still blocked (its timeout already marked the session).
var errOpenBlocked = errors.New("stream opens blocked")

// openUnlessRetired opens a stream on c unless it has been retired. The open
// is counted in c.opening so that retire can wait for it (see agentConn.mu);
// a pick never waits on a retire.
//
// yamux blocks an open while the session already has a full backlog of
// opens the agent has not acknowledged (a stalled agent), so the open is
// bounded by wait. An open given up on still finishes in the background:
// it stays counted until then, and a stream it yields is closed unused.
func openUnlessRetired(c *agentConn, wait time.Duration) (*yamux.Stream, error) {
	c.mu.Lock()
	switch {
	case c.retired:
		c.mu.Unlock()
		return nil, errRetired
	case c.stuck > 0:
		// An earlier open is still blocked: the backlog is full, and another
		// open would only add a blocked goroutine.
		c.mu.Unlock()
		return nil, errOpenBlocked
	}
	c.opening++
	c.mu.Unlock()
	// One open's state, guarded by c.mu, so that giving up on it and its
	// completion each update the session's counts in one step.
	var (
		s         *yamux.Stream
		err       error
		finished  bool
		abandoned bool
	)
	done := make(chan struct{})
	go func() {
		st, e := c.sess.OpenStream()
		c.mu.Lock()
		s, err, finished = st, e, true
		c.opening--
		if abandoned {
			c.stuck--
		}
		c.wakeIfIdleLocked()
		gaveUp := abandoned
		c.mu.Unlock()
		if gaveUp && st != nil {
			_ = st.Close() // nobody will use it
		}
		close(done)
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		c.mu.Lock()
		if !finished {
			abandoned = true
			c.stuck++ // given up on: no longer one retireForDrain waits for
			c.wakeIfIdleLocked()
			c.mu.Unlock()
			// An open blocks only when the agent has stopped taking streams (a
			// full backlog of unacknowledged opens) or the tunnel stopped
			// writing: the session is stalled, however short this wait was.
			// Keep it out of picks, whoever was opening.
			c.coolDownFor(2 * acceptWait)
			return nil, errOpenTimeout
		}
		c.mu.Unlock()
		<-done // it finished just as the wait ran out: use it
	}
	return s, err
}

// acceptWait bounds the wait for a version 2 agent's accept byte. The request
// head is only sent after it, so a timeout is retried on another agent.
var acceptWait = 15 * time.Second

// retire takes a draining agent's session out of the pool without closing it:
// its in-flight streams keep running until the agent closes the session. Once
// marked, no new stream is opened on it (see openUnlessRetired).
func (e *Edge) retire(c *agentConn) {
	c.mu.Lock()
	already := c.retired
	c.retired = true
	c.mu.Unlock()
	if already {
		return
	}
	e.reg.take(c.fp, c.sess)
	c.stat.SetDraining()
	e.log.Info("agent.draining", "peer_fp", c.fp)
}

// retireForDrain is retire for the agent's drain request: it also waits, up
// to tunnel.RetireWait, for stream opens already past the retired check, so their
// opening frames reach the agent before the acknowledgement does.
func (e *Edge) retireForDrain(c *agentConn) {
	e.retire(c)
	c.mu.Lock()
	if c.liveOpensLocked() == 0 {
		c.mu.Unlock()
		return
	}
	if c.idle == nil {
		c.idle = make(chan struct{})
	}
	idle := c.idle
	c.mu.Unlock()
	select {
	case <-idle:
	case <-time.After(tunnel.RetireWait):
		// Acknowledging anyway: a stream still being opened may reach the
		// agent after it stops accepting, and its client be dropped.
		e.log.Warn("agent.drain_ack_early", "peer_fp", c.fp, "waited", tunnel.RetireWait.String())
	}
}

func (e *Edge) acceptIngress(ctx context.Context, ln net.Listener) {
	e.acceptLoop(ctx, ln, "ingress", func(conn net.Conn) {
		e.drainWG.Add(1)
		go func() {
			defer e.drainWG.Done()
			e.handleIngress(conn)
		}()
	})
}

func (e *Edge) handleIngress(conn net.Conn) {
	connID := obs.NewID()
	log := e.log.With("conn_id", connID, "client_addr", conn.RemoteAddr().String())

	if !e.sem.tryAcquire() {
		e.state.Failure(obs.ReasonMaxConnections)
		log.Warn("ingress.rejected", "reason", "max_connections")
		// Bound the 503 write: on the TLS ingress it first runs the handshake,
		// which would otherwise wait forever on a client that sends nothing.
		_ = conn.SetDeadline(time.Now().Add(readHeaderDeadline(e.cfg.Ingress.ReadHeaderTimeout.Duration())))
		errpage.Write(conn, 503, "Service Unavailable", "Too many connections", connID)
		_ = conn.Close()
		return
	}
	defer e.sem.release()

	// The public listener always gets a read/handshake deadline (slow-loris
	// protection); a non-positive config value falls back to the default rather
	// than disabling it.
	_ = conn.SetReadDeadline(time.Now().Add(readHeaderDeadline(e.cfg.Ingress.ReadHeaderTimeout.Duration())))
	head, host, err := readRequestHead(conn, maxHeaderBytes)
	if errors.Is(err, errNoRequest) && closedWithoutRequest(conn) {
		// Connected and closed, reset, or idled out without asking for
		// anything: a TCP health check, a port scan, or a browser preconnect
		// that finished TLS but sent no request. Nothing to answer and not a
		// malformed request. A connection cut off at the deadline is counted
		// separately (coen_ingress_header_timeouts_total), so a flood of idle
		// connections stays visible; one that simply closed is not counted.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			e.state.HeaderTimeout()
		}
		log.Debug("ingress.closed_early", "error", err.Error())
		_ = conn.Close()
		return
	}
	if err != nil {
		e.state.Failure(obs.ReasonBadRequest)
		log.Warn("ingress.bad_request", "error", err.Error())
		errpage.Write(conn, 400, "Bad Request", "Malformed request", connID)
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear before streaming
	log = log.With("host", host)
	log.Debug("ingress.accept")

	rs, ok := e.routes.Match(host)
	if !ok {
		e.state.Failure(obs.ReasonNoRoute)
		log.Warn("ingress.no_route")
		errpage.Write(conn, 404, "Not Found", "No route for host", connID)
		_ = conn.Close()
		return
	}
	if !rs.sem.tryAcquire() {
		rs.stats.Failure(obs.ReasonRouteMaxConnections)
		log.Warn("ingress.rejected", "reason", "route_max_connections")
		errpage.Write(conn, 503, "Service Unavailable", "Too many connections", connID)
		_ = conn.Close()
		return
	}
	defer rs.sem.release()

	stream, chosen, refused := e.dispatch(rs, connID, conn.RemoteAddr().String(), host, head, log)
	if refused != nil {
		errpage.Write(conn, refused.code, refused.reason, refused.detail, connID)
		_ = conn.Close()
		return
	}
	chosen.stat.Commit()
	defer chosen.stat.StreamClosed()
	e.state.StreamOpened(rs.stats)
	sb := rs.stats.Bytes()
	log.Debug("stream.open")
	// Bytes are counted as they cross the tunnel stream, in both directions,
	// so the edge and the agent agree (an Alt-Svc line the edge adds is not
	// tunnel traffic).
	counted := &countingConn{Conn: stream, in: sb.AddIn, out: sb.AddOut}
	var tunnelSide net.Conn = counted
	if v, _ := e.altSvc.Load().(string); v != "" {
		tunnelSide = newAltSvcConn(tunnelSide, v) // advertise HTTP/3
	}
	client := proxy.NewIdleConn(conn, e.cfg.Ingress.IdleTimeout.Duration())
	// The head goes to the agent first: through the pipe, or already sent
	// with the preamble (version 2), in which case it is counted here.
	prefix, preSent := head, int64(0)
	if chosen.v2 { // the head went with the preamble
		prefix, preSent = nil, int64(len(head))
		sb.AddIn(preSent)
	}
	src := net.Conn(client)
	if len(prefix) > 0 {
		src = proxy.WithPrefix(client, prefix)
	}
	_, _, _ = proxy.Pipe(src, tunnelSide)
	e.state.StreamClosed(rs.stats)
	// Both copies have ended, so the totals are settled: tunnel bytes, as
	// the metrics count them.
	log.Debug("stream.closed", "bytes_in", counted.inTotal+preSent, "bytes_out", counted.outTotal)
}

// refusal is how a request that could not be handed to an agent is answered.
type refusal struct {
	code           int
	reason, detail string
}

var (
	noAgent      = &refusal{502, "Bad Gateway", "No agent connected"}
	streamFailed = &refusal{502, "Bad Gateway", "Tunnel stream failed"}
)

// dispatch hands a request for host, whose HTTP/1.1 head is head, to one of
// rs's agents. It returns the agent's stream and session, with the preamble
// sent and, for a version 2 agent, the head too (for a version 1 agent the
// caller sends the head). Otherwise it has recorded the failure and returns
// how to answer the client. The caller holds rs's connection slot.
func (e *Edge) dispatch(rs *routeState, connID, clientAddr, host string, head []byte, log *slog.Logger) (stream net.Conn, chosen *agentConn, refused *refusal) {
	// Lazy backend dial: the stream (and thus the agent's Dial) is opened only
	// now that a complete, valid request head has arrived. The balancer picks a
	// session; if it turns out to be dead (a silent partition the keepalive has
	// not caught yet, or an agent shutting down), it is evicted and the next
	// one is tried. Nothing has been sent to the client yet, so retrying is safe.
	cands := e.untried(rs, nil)
	if len(cands) == 0 {
		rs.stats.Failure(obs.ReasonNoAgent)
		log.Warn("ingress.no_agent", "agent_fp", rs.label)
		return nil, nil, noAgent
	}
	// Encode the stream preamble once, before touching any agent: an
	// oversized one (a huge Host) is a property of the request.
	preamble, err := tunnel.EncodePreamble(tunnel.Preamble{ConnID: connID, ClientAddr: clientAddr, Host: host, EdgeVersion: e.cfg.Version})
	if err != nil {
		rs.stats.Failure(obs.ReasonStreamError)
		log.Warn("stream.preamble_error", "error", err.Error())
		return nil, nil, streamFailed
	}
	tried := map[*agentConn]bool{} // sessions attempted for this request
	turn := rs.nextTurn()
	// Each attempt waits at most acceptWait for an accept, and all attempts
	// together at most twice that: room for one stalled agent and a full try
	// elsewhere, without a request waiting on several stalled agents in turn.
	deadline := time.Now().Add(2 * acceptWait)
	// When every attempt found the agent draining or refusing, there is no
	// agent to serve the request (no_agent); otherwise it is a stream error.
	attempts, unavailable := 0, 0
	for chosen == nil {
		wait := time.Until(deadline)
		var c *agentConn
		if wait > 0 {
			c = rs.pickReserve(cands, tried, turn)
			if c == nil {
				// Every listed session was tried. Sessions that joined since
				// (an agent restarted during the attempts) still get a turn.
				if fresh := e.untried(rs, tried); len(fresh) > 0 {
					cands = fresh
					continue
				}
			}
		}
		if c == nil {
			// Out of sessions or out of time. If every attempt found the
			// agent draining, refusing, or gone, there is no agent to serve
			// the request (no_agent); otherwise it is a tunnel stream error.
			why := "nothing left to try"
			if wait <= 0 {
				why = "deadline passed"
			}
			if unavailable == attempts {
				rs.stats.Failure(obs.ReasonNoAgent)
				log.Warn("ingress.no_agent", "agent_fp", rs.label, "reason", "all agents draining, refusing, or gone", "attempts", attempts, "ended", why)
				return nil, nil, noAgent
			}
			rs.stats.Failure(obs.ReasonStreamError)
			log.Warn("stream.no_session", "agent_fp", rs.label, "attempts", attempts, "unavailable", unavailable, "ended", why)
			return nil, nil, streamFailed
		}
		attempts++
		// An attempt waits at most acceptWait, so a stalled agent leaves time
		// to try another. With no other session left to try there is nothing
		// to save time for: a slow but working tunnel (its accept byte queued
		// behind bulk data) then gets the rest of the request's time.
		// A session cooling down after a failure (a stalled one, say) gets no
		// more than that, so a silent agent cannot hold every request for the
		// whole deadline.
		attemptWait := min(wait, acceptWait)
		if c.coolUntil.Load() <= time.Now().UnixNano() && !slices.ContainsFunc(cands, func(o *agentConn) bool { return !tried[o] }) {
			// None listed is left; one that joined since still counts. (On
			// the first attempt the list was read just now.)
			var fresh []*agentConn
			if attempts > 1 {
				fresh = e.untried(rs, tried)
			}
			if len(fresh) > 0 {
				cands = append(cands, fresh...)
			} else {
				attemptWait = wait
			}
		}
		cooled := c.coolUntil.Load()
		s, outcome, err := e.tryAgent(c, preamble, head, attemptWait)
		switch outcome {
		case attemptOK:
			stream, chosen = s, c
			// It works again: back into normal picks, unless a concurrent
			// request has meanwhile cooled it down (again).
			c.coolUntil.CompareAndSwap(cooled, 0)
		case attemptUnavailable:
			unavailable++
			log.Debug("stream.unavailable", "agent_fp", c.fp, "error", err.Error())
		case attemptFailed:
			log.Warn("stream.open_error", "agent_fp", c.fp, "error", err.Error())
		case attemptUnknown:
			// The agent may already have the request: never send it twice.
			rs.stats.Failure(obs.ReasonStreamError)
			log.Warn("stream.send_error", "agent_fp", c.fp, "error", err.Error())
			return nil, nil, streamFailed
		}
	}
	return stream, chosen, nil
}
