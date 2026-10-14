package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/errpage"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// routeState is the per-route value stored in the matcher: the owning agent
// fingerprint, an optional per-route connection cap, and the route's counters
// (nil-safe, so a routeState built without stats still works).
type routeState struct {
	fingerprint string
	sem         *semaphore
	stats       *obs.RouteStats
}

type Edge struct {
	cfg     *config.EdgeConfig
	log     *slog.Logger
	state   *obs.State
	tunTLS  *tls.Config
	allowed map[string]bool
	reg     *registry
	routes  *route.Matcher[*routeState]
	sem     *semaphore // global ingress connection cap
	drainWG sync.WaitGroup
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
	state.ExpectAgents(e.allowed)
	entries := make([]route.Entry[*routeState], 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		entries = append(entries, route.Entry[*routeState]{Pattern: r.Host, Value: &routeState{fingerprint: r.AgentFingerprint, sem: newSemaphore(r.MaxConnections), stats: state.Route(route.Normalize(r.Host))}})
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
	return e.Serve(ctx, tunLn, ingressLn)
}

func (e *Edge) listenIngress() (net.Listener, error) {
	switch e.cfg.Ingress.Mode {
	case "standalone":
		cert, err := tls.LoadX509KeyPair(e.cfg.Ingress.TLS.Cert, e.cfg.Ingress.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("load public cert: %w", err)
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
	e.log.Info("tunnel.listen", "address", tunLn.Addr().String())
	e.log.Info("ingress.listen", "mode", e.cfg.Ingress.Mode, "address", ingressLn.Addr().String())
	go func() {
		<-ctx.Done()
		_ = tunLn.Close()
		_ = ingressLn.Close()
	}()
	go e.acceptTunnel(ctx, tunLn)
	e.acceptIngress(ctx, ingressLn) // returns once ingressLn is closed
	e.drain()                       // no new handlers can start now
	e.reg.closeAll()
	return nil
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
	if !e.reg.register(fp, session) {
		// A live agent already owns this fingerprint. Keep it and drop this
		// connection so a duplicate cert (or a stray reconnect) cannot disrupt a
		// serving agent. This is not counted as a successful handshake.
		e.state.HandshakeDuplicate()
		e.log.Warn("agent.duplicate_fingerprint", "peer_fp", fp)
		_ = session.Close()
		return
	}
	e.state.HandshakeOK() // count only a fully accepted agent, not a refused duplicate
	e.state.AgentConnected(fp, tlsConn.RemoteAddr().String())
	e.log.Info("agent.connected", "peer_fp", fp, "remote_addr", tlsConn.RemoteAddr().String())

	<-session.CloseChan()
	if e.reg.remove(fp, session) {
		e.state.AgentDisconnected(fp)
		e.log.Info("agent.disconnected", "peer_fp", fp)
	}
}

// evict removes a dead session so a reconnecting agent can register at once
// instead of being refused as a duplicate while requests fail until the tunnel
// keepalive fires. remove is session-guarded, so a concurrent reconnect is safe.
func (e *Edge) evict(fp string, session *yamux.Session) {
	if e.reg.remove(fp, session) {
		e.state.AgentDisconnected(fp)
		e.log.Info("agent.disconnected", "peer_fp", fp)
	}
	_ = session.Close()
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

	session, ok := e.reg.get(rs.fingerprint)
	if !ok {
		rs.stats.Failure(obs.ReasonNoAgent)
		log.Warn("ingress.no_agent", "agent_fp", rs.fingerprint)
		errpage.Write(conn, 502, "Bad Gateway", "No agent connected", connID)
		_ = conn.Close()
		return
	}
	// Lazy backend dial: the stream (and thus the agent's Dial) is opened only
	// now that a complete, valid request head has arrived.
	stream, err := session.OpenStream()
	if err != nil {
		rs.stats.Failure(obs.ReasonStreamError)
		log.Warn("stream.open_error", "error", err.Error())
		// The session is dead (a silent partition the tunnel keepalive has not
		// detected yet).
		e.evict(rs.fingerprint, session)
		errpage.Write(conn, 502, "Bad Gateway", "No agent connected", connID)
		_ = conn.Close()
		return
	}
	if err := tunnel.WritePreamble(stream, tunnel.Preamble{ConnID: connID, ClientAddr: conn.RemoteAddr().String(), Host: host, EdgeVersion: e.cfg.Version}); err != nil {
		rs.stats.Failure(obs.ReasonStreamError)
		log.Warn("stream.preamble_error", "error", err.Error())
		_ = stream.Close()
		// A failed write on a session that has since shut down means the
		// tunnel is gone, as on the open failure above; a live session (for
		// example an oversized preamble) is kept.
		if session.IsClosed() {
			e.evict(rs.fingerprint, session)
		}
		errpage.Write(conn, 502, "Bad Gateway", "Tunnel stream failed", connID)
		_ = conn.Close()
		return
	}
	e.state.StreamOpened(rs.stats)
	sb := rs.stats.Bytes()
	log.Debug("stream.open")
	client := proxy.NewIdleConn(conn, e.cfg.Ingress.IdleTimeout.Duration())
	in, out, _ := proxy.PipeProgress(proxy.WithPrefix(client, head), stream, sb.AddIn, sb.AddOut)
	e.state.StreamClosed(rs.stats)
	log.Debug("stream.closed", "bytes_in", in, "bytes_out", out)
}
