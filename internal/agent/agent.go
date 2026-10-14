package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/errpage"
	"github.com/baspeters/coen/internal/netx"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// agentRoute is the per-route value stored in the matcher: the backend address
// and the route's counters (nil-safe).
type agentRoute struct {
	service string
	stats   *obs.RouteStats
}

type Agent struct {
	cfg     *config.AgentConfig
	log     *slog.Logger
	state   *obs.State
	tlsCfg  *tls.Config
	routes  *route.Matcher[agentRoute] // host -> local backend service and its counters
	version string                     // build version, for edge/agent skew detection

	mu          sync.Mutex
	draining    bool
	inflight    sync.WaitGroup
	versionWarn sync.Once
}

// drainStreamsFor stops accepting new streams, then waits up to d for
// in-flight streams to finish.
func (a *Agent) drainStreamsFor(d time.Duration) {
	a.refuseNew()
	obs.DrainWait(a.log, &a.inflight, d)
}

// refuseNew makes serveStream refuse every stream from now on.
func (a *Agent) refuseNew() {
	a.mu.Lock()
	a.draining = true
	a.mu.Unlock()
}

func New(cfg *config.AgentConfig, log *slog.Logger, state *obs.State) (*Agent, error) {
	pool, cert, err := tunnel.LoadMaterial(cfg.Edge.CA, cfg.Edge.Cert, cfg.Edge.Key, "client cert")
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.Edge.Address)
	if err != nil {
		return nil, fmt.Errorf("edge.address %q: %w", cfg.Edge.Address, err)
	}
	if cert.Leaf != nil {
		state.SetSelfFingerprint(pki.Fingerprint(cert.Leaf))
	}
	entries := make([]route.Entry[agentRoute], 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		entries = append(entries, route.Entry[agentRoute]{Pattern: r.Host, Value: agentRoute{service: r.Service, stats: state.Route(route.Normalize(r.Host))}})
	}
	return &Agent{cfg: cfg, log: log, state: state, tlsCfg: tunnel.ClientTLSConfig(pool, cert, host), routes: route.Build(entries), version: cfg.Version}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	min := a.cfg.Reconnect.MinBackoff.Duration()
	max := a.cfg.Reconnect.MaxBackoff.Duration()
	backoff := min
	for ctx.Err() == nil {
		stable, err := a.connectOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		a.state.SetDisconnected()
		if err != nil {
			a.log.Warn("tunnel.closed", "reason", err.Error())
			a.state.SetError(err.Error())
		}
		// Reset the backoff only when the tunnel actually stayed up long enough
		// to be a real session (see connectOnce); an immediately-rejected
		// handshake keeps backing off rather than reconnecting ~1/s.
		if stable {
			backoff = min
		}
		wait := withJitter(backoff)
		a.log.Info("reconnect.scheduled", "backoff", wait.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		a.state.Reconnect()
		if backoff *= 2; backoff > max {
			backoff = max
		}
	}
	return nil
}

func (a *Agent) connectOnce(ctx context.Context) (stable bool, err error) {
	a.log.Info("edge.dial", "address", a.cfg.Edge.Address)
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", a.cfg.Edge.Address)
	if err != nil {
		a.state.HandshakeFail()
		return false, fmt.Errorf("dial edge: %w", err)
	}
	conn := tls.Client(raw, a.tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		a.state.HandshakeFail()
		_ = raw.Close()
		return false, fmt.Errorf("tls handshake: %w", err)
	}
	fp := pki.Fingerprint(conn.ConnectionState().PeerCertificates[0])
	// Version 2 features (drain handshake, stream accept byte) are used only
	// when both sides negotiated them in the TLS handshake.
	v2 := conn.ConnectionState().NegotiatedProtocol == tunnel.ALPNv2
	if pin := a.cfg.Edge.EdgeFingerprint; pin != "" && pin != fp {
		_ = conn.Close()
		a.state.HandshakeFail()
		return false, fmt.Errorf("edge fingerprint mismatch: got %s, want %s", fp, pin)
	}
	a.state.HandshakeOK()
	a.state.SetConnected(fp)
	a.log.Info("tunnel.established", "peer_fp", fp, "tls", tlsVersion(conn.ConnectionState().Version))
	// A session is "stable" (worth resetting the reconnect backoff for) only if
	// it lives at least min_backoff. A handshake the edge accepts then rejects
	// (unauthorized or duplicate fingerprint) returns below in well under that,
	// so it keeps backing off instead of storming ~1/s.
	connectedAt := time.Now()
	minBackoff := a.cfg.Reconnect.MinBackoff.Duration()

	session, err := tunnel.ClientSession(conn)
	if err != nil {
		_ = conn.Close()
		return time.Since(connectedAt) >= minBackoff, fmt.Errorf("yamux client: %w", err)
	}
	defer session.Close()
	// On cancellation, drain in-flight streams (bounded) then close the session
	// so AcceptStream unblocks and Run can return promptly on shutdown.
	acceptCtx, stopAccept := context.WithCancel(context.Background())
	defer stopAccept()
	mainStopped := make(chan struct{}) // the main accept loop has ended
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			a.shutdownSession(ctx, session, v2, stopAccept, mainStopped)
		case <-mainStopped:
		}
	}()
	for {
		stream, err := session.AcceptStreamWithContext(acceptCtx)
		if err != nil {
			close(mainStopped)
			// If shutdown began (even as the session died on its own),
			// shutdownSession owns the session: wait until it has drained
			// the in-flight streams and closed it. Otherwise this returns
			// at once.
			<-shutdownDone
			return time.Since(connectedAt) >= minBackoff, fmt.Errorf("accept stream: %w", err)
		}
		a.serveStream(ctx, stream, v2)
	}
}

// shutdownSession stops serving the session on shutdown.
//
// With an edge that supports the graceful handoff (negotiated in the TLS
// handshake, see tunnel.ALPNv2), the agent asks to be taken out of the
// edge's pool. Frames arrive in order, so once the edge acknowledges, every
// stream it opened to this agent is already queued here. GoAway then refuses
// any further stream, the main accept loop is stopped, and this goroutine
// alone accepts and serves the queued streams until the queue stays empty.
// Only then does it drain the in-flight streams and close the session.
//
// With an older edge (no drain support negotiated) it keeps the old behaviour:
// no GoAway, which an older edge would treat as a dead session and close,
// cutting the streams still draining. New streams are refused while the
// in-flight ones drain, and that edge has no way to retry them elsewhere.
//
// The acknowledgement wait counts against drain_timeout and takes at most
// half of it. It must be at least tunnel.MinAckWait, so with a drain_timeout
// under minHandoff the agent does not wait for it: it sends the request in
// the background (so the edge still takes it out of the pool, and a
// replacement with the same certificate is not refused as a duplicate) and
// GoAway; streams already on their way are refused without the accept byte
// (the edge retries them elsewhere), and the in-flight ones get the whole
// drain_timeout. On a session that is already closed there is nothing to
// hand off.
func (a *Agent) shutdownSession(ctx context.Context, session *yamux.Session, v2 bool, stopAccept context.CancelFunc, mainStopped <-chan struct{}) {
	budget := a.cfg.Drain.Duration()
	start := time.Now()
	switch {
	case !v2 || budget <= 0 || session.IsClosed():
		// No handoff: an older edge, no draining at all, or a dead session.
	case budget < minHandoff:
		// Neither is waited for, so the in-flight streams keep the whole
		// budget; both end with the session at the latest.
		a.refuseNew()
		go tunnel.RequestDrain(session, budget)
		go func() { _ = session.GoAway() }()
	default:
		// Send GoAway even if the drain acknowledgement does not come in
		// time: this edge then retires the session the next time it picks
		// it, and only the ordering guarantee for streams opened at that
		// moment is lost. The wait is never
		// shorter than the edge's own (budget/2 >= tunnel.MinAckWait here).
		ackWait := min(drainAckTimeout, budget/2)
		if !tunnel.RequestDrain(session, ackWait) {
			// The edge may still open streams until it sees GoAway. Those
			// arriving after it are reset by yamux, which the edge retries
			// elsewhere; those before it are already queued here.
			a.log.Warn("drain.no_ack", "waited", ackWait.String())
		}
		// GoAway can block on a stalled tunnel; do not let it hold up the
		// shutdown beyond a short bound, so at least a quarter of the budget
		// is left for the in-flight streams.
		netx.Bounded(min(goAwayWait, budget/4), func() { _ = session.GoAway() })
		stopAccept()
		select {
		case <-mainStopped:
		case <-session.CloseChan():
		}
		for {
			qctx, cancel := context.WithTimeout(context.Background(), backlogQuiet)
			stream, err := session.AcceptStreamWithContext(qctx)
			cancel()
			if err != nil {
				break
			}
			if budget-time.Since(start) < minServe {
				// Too little drain time left to serve it: refuse it (no
				// accept byte), so the edge retries it on another agent.
				_ = stream.Close()
				continue
			}
			a.serveStream(ctx, stream, true)
		}
	}
	remaining := budget - time.Since(start)
	if budget > 0 && remaining <= 0 {
		remaining = time.Millisecond // budget spent: a last look, then close
	}
	a.drainStreamsFor(remaining)
	_ = session.Close()
}

// serveStream handles stream on its own goroutine, counted as in flight, unless
// the agent is already draining, in which case the stream is refused (closed
// without the accept byte, so a version 2 edge retries it elsewhere). accept
// says whether to send the accept byte (version 2 sessions).
func (a *Agent) serveStream(ctx context.Context, stream net.Conn, accept bool) {
	a.mu.Lock()
	if a.draining {
		a.mu.Unlock()
		_ = stream.Close()
		return
	}
	a.inflight.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.inflight.Done()
		a.handleStream(ctx, stream, accept)
	}()
}

// drainAckTimeout bounds the wait for the edge to acknowledge a drain request;
// tunnel.MinAckWait floors it, so a slow acknowledgement still arrives.
// goAwayWait bounds sending GoAway on a stalled tunnel. backlogQuiet is how
// long the accept queue must stay empty, after GoAway, before the agent stops
// accepting. yamux resets every stream that arrives after the agent's GoAway,
// so the queue is complete once GoAway is sent; the short wait only lets the
// accept loop drain it.
const (
	drainAckTimeout = 3 * time.Second
	goAwayWait      = time.Second
	backlogQuiet    = 50 * time.Millisecond
	minHandoff      = 2 * tunnel.MinAckWait  // the shortest drain_timeout that gets a handoff
	minServe        = 500 * time.Millisecond // drain time a queued stream needs to be taken
)

// preambleReadTimeout bounds how long handleStream waits for a stream's preamble.
const preambleReadTimeout = 10 * time.Second

func (a *Agent) handleStream(ctx context.Context, stream net.Conn, accept bool) {
	defer stream.Close()
	if accept {
		// Take the stream on arrival, before reading anything on it, so an
		// edge that sees it close without this byte knows the agent refused
		// it (draining, or its accept queue full) and read nothing of the request.
		if err := tunnel.Accept(stream); err != nil {
			a.log.Debug("stream.accept_error", "error", err.Error())
			return
		}
	}
	// Bound the preamble read so a stream that never sends one (a hung or
	// misbehaving edge) cannot pin this goroutine indefinitely.
	_ = stream.SetReadDeadline(time.Now().Add(preambleReadTimeout))
	p, err := tunnel.ReadPreamble(stream)
	if err != nil {
		if tunnel.IsTeardown(err) {
			// The stream or session closed before a preamble arrived, as on a
			// routine edge restart. Not a protocol fault, so not counted.
			a.log.Debug("stream.closed_before_preamble", "error", err.Error())
			return
		}
		a.state.Failure(obs.ReasonPreambleError)
		a.log.Warn("stream.preamble_error", "error", err.Error())
		return
	}
	_ = stream.SetReadDeadline(time.Time{}) // clear before streaming
	log := a.log.With("conn_id", p.ConnID, "client_addr", p.ClientAddr, "host", p.Host)
	if p.EdgeVersion != a.version {
		// Warn once per process on an edge/agent version skew (an empty
		// EdgeVersion means the edge predates this field, i.e. an older build).
		a.versionWarn.Do(func() {
			log.Warn("version.mismatch", "edge_version", p.EdgeVersion, "agent_version", a.version)
		})
	}
	rt, ok := a.routes.Match(p.Host)
	if !ok {
		a.state.Failure(obs.ReasonNoRoute)
		log.Warn("stream.no_route", "host", p.Host)
		errpage.Write(stream, 502, "Bad Gateway", "No backend for host", p.ConnID)
		return
	}
	log.Debug("stream.accept")
	svcAddr := rt.service
	// The dial is part of an accepted, in-flight stream, so a shutdown signal
	// must not cancel it: the drain lets it finish (bounded by the dial timeout
	// and drain_timeout) instead of failing a healthy backend as dial_error.
	svc, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.WithoutCancel(ctx), "tcp", svcAddr)
	if err != nil {
		rt.stats.Failure(obs.ReasonDialError)
		log.Error("service.dial_error", "address", svcAddr, "error", err.Error())
		errpage.Write(stream, 502, "Bad Gateway", "Backend unreachable", p.ConnID)
		return
	}
	a.state.StreamOpened(rt.stats)
	sb := rt.stats.Bytes()
	log.Debug("service.dial", "address", svcAddr)
	in, out, _ := proxy.PipeProgress(stream, svc, sb.AddIn, sb.AddOut)
	a.state.StreamClosed(rt.stats)
	log.Debug("stream.closed", "bytes_in", in, "bytes_out", out)
}

func withJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
