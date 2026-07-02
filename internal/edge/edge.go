package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/proxy"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

type Edge struct {
	cfg     *config.EdgeConfig
	log     *slog.Logger
	state   *obs.State
	tunTLS  *tls.Config
	allowed map[string]bool
	session atomic.Pointer[yamux.Session]
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
	e := &Edge{cfg: cfg, log: log, state: state, tunTLS: tunnel.ServerTLSConfig(pool, cert), allowed: map[string]bool{}}
	for _, fp := range cfg.Tunnel.AllowedAgentFingerprints {
		e.allowed[fp] = true
	}
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
		if s := e.session.Load(); s != nil {
			_ = s.Close()
		}
	}()
	go e.acceptTunnel(ctx, tunLn)
	e.acceptIngress(ctx, ingressLn)
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
	e.state.SetConnected(fp)
	if prev := e.session.Swap(session); prev != nil {
		_ = prev.Close()
	}
	e.log.Info("agent.connected", "peer_fp", fp)

	<-session.CloseChan()
	if e.session.CompareAndSwap(session, nil) {
		e.state.SetDisconnected()
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
	log.Info("ingress.accept")
	session := e.session.Load()
	if session == nil {
		log.Warn("ingress.no_agent")
		writeBadGateway(conn)
		_ = conn.Close()
		return
	}
	stream, err := session.OpenStream()
	if err != nil {
		log.Warn("stream.open_error", "error", err.Error())
		writeBadGateway(conn)
		_ = conn.Close()
		return
	}
	if err := tunnel.WritePreamble(stream, tunnel.Preamble{ConnID: connID, ClientAddr: conn.RemoteAddr().String()}); err != nil {
		log.Warn("stream.preamble_error", "error", err.Error())
		_ = stream.Close()
		_ = conn.Close()
		return
	}
	e.state.StreamOpened()
	log.Debug("stream.open")
	in, out, _ := proxy.Pipe(conn, stream)
	e.state.StreamClosed(in, out)
	log.Info("stream.closed", "bytes_in", in, "bytes_out", out)
}

func writeBadGateway(conn net.Conn) {
	const body = "coen: no agent connected\n"
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
