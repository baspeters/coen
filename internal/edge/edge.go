package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
)

// routeState is the per-route value stored in the matcher: the owning agent
// fingerprint and an optional per-route connection cap.
type routeState struct {
	fingerprint string
	sem         *semaphore
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
}

func New(cfg *config.EdgeConfig, log *slog.Logger, state *obs.State) (*Edge, error) {
	caPEM, err := os.ReadFile(cfg.Tunnel.CA)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool, err := pki.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(cfg.Tunnel.Cert, cfg.Tunnel.Key)
	if err != nil {
		return nil, fmt.Errorf("load edge cert: %w", err)
	}
	e := &Edge{cfg: cfg, log: log, state: state, tunTLS: tunnel.ServerTLSConfig(pool, cert), allowed: cfg.AllowedFingerprints(), reg: newRegistry(), sem: newSemaphore(cfg.Ingress.MaxConnections)}
	entries := make([]route.Entry[*routeState], 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		entries = append(entries, route.Entry[*routeState]{Pattern: r.Host, Value: &routeState{fingerprint: r.AgentFingerprint, sem: newSemaphore(r.MaxConnections)}})
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
		return tls.Listen("tcp", e.cfg.Ingress.Listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
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
	e.acceptIngress(ctx, ingressLn)
	e.reg.closeAll()
	return nil
}

func (e *Edge) acceptTunnel(ctx context.Context, ln net.Listener) {
	for ctx.Err() == nil {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go e.serveAgent(conn)
	}
}

// handshakeTimeout bounds the TLS handshake on the internet-facing tunnel
// listener so an unauthenticated peer cannot pin a goroutine/fd indefinitely.
const handshakeTimeout = 10 * time.Second

func (e *Edge) serveAgent(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		e.state.HandshakeFail()
		e.log.Warn("agent.tls_handshake", "verify_result", "fail", "error", err.Error())
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
	e.state.HandshakeOK()
	if prev := e.reg.set(fp, session); prev != nil {
		_ = prev.Close()
	}
	e.state.AgentConnected(fp)
	e.log.Info("agent.connected", "peer_fp", fp)

	<-session.CloseChan()
	if e.reg.remove(fp, session) {
		e.state.AgentDisconnected(fp)
		e.log.Info("agent.disconnected", "peer_fp", fp)
	}
}

func (e *Edge) acceptIngress(ctx context.Context, ln net.Listener) {
	for ctx.Err() == nil {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go e.handleIngress(conn)
	}
}

func (e *Edge) handleIngress(conn net.Conn) {
	connID := obs.NewID()
	log := e.log.With("conn_id", connID, "client_addr", conn.RemoteAddr().String())

	if !e.sem.tryAcquire() {
		log.Warn("ingress.rejected", "reason", "max_connections")
		writeStatus(conn, 503, "Service Unavailable", "coen: too many connections\n")
		_ = conn.Close()
		return
	}
	defer e.sem.release()

	head, host, err := readRequestHead(conn, maxHeaderBytes)
	if err != nil {
		log.Warn("ingress.bad_request", "error", err.Error())
		writeStatus(conn, 400, "Bad Request", "coen: bad request\n")
		_ = conn.Close()
		return
	}
	log = log.With("host", host)
	log.Info("ingress.accept")

	rs, ok := e.routes.Match(host)
	if !ok {
		log.Warn("ingress.no_route")
		writeStatus(conn, 404, "Not Found", "coen: no route for host\n")
		_ = conn.Close()
		return
	}
	if !rs.sem.tryAcquire() {
		log.Warn("ingress.rejected", "reason", "route_max_connections")
		writeStatus(conn, 503, "Service Unavailable", "coen: too many connections\n")
		_ = conn.Close()
		return
	}
	defer rs.sem.release()

	session, ok := e.reg.get(rs.fingerprint)
	if !ok {
		log.Warn("ingress.no_agent", "agent_fp", rs.fingerprint)
		writeStatus(conn, 502, "Bad Gateway", "coen: no agent connected\n")
		_ = conn.Close()
		return
	}
	// Lazy backend dial: the stream (and thus the agent's Dial) is opened only
	// now that a complete, valid request head has arrived.
	stream, err := session.OpenStream()
	if err != nil {
		log.Warn("stream.open_error", "error", err.Error())
		writeStatus(conn, 502, "Bad Gateway", "coen: no agent connected\n")
		_ = conn.Close()
		return
	}
	if err := tunnel.WritePreamble(stream, tunnel.Preamble{ConnID: connID, ClientAddr: conn.RemoteAddr().String(), Host: host}); err != nil {
		log.Warn("stream.preamble_error", "error", err.Error())
		_ = stream.Close()
		_ = conn.Close()
		return
	}
	e.state.StreamOpened()
	log.Debug("stream.open")
	in, out, _ := proxy.Pipe(proxy.WithPrefix(conn, head), stream)
	e.state.StreamClosed(in, out)
	log.Info("stream.closed", "bytes_in", in, "bytes_out", out)
}
