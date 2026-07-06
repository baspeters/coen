package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
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
)

type Agent struct {
	cfg     *config.AgentConfig
	log     *slog.Logger
	state   *obs.State
	tlsCfg  *tls.Config
	routes  *route.Matcher[string] // host -> local backend service address
	version string                 // build version, for edge/agent skew detection

	mu          sync.Mutex
	draining    bool
	inflight    sync.WaitGroup
	versionWarn sync.Once
}

// drainStreams stops accepting new streams, then waits up to cfg.Drain for
// in-flight streams to finish.
func (a *Agent) drainStreams() {
	a.mu.Lock()
	a.draining = true
	a.mu.Unlock()
	obs.DrainWait(a.log, &a.inflight, a.cfg.Drain.Duration())
}

func New(cfg *config.AgentConfig, log *slog.Logger, state *obs.State) (*Agent, error) {
	caPEM, err := os.ReadFile(cfg.Edge.CA)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool, err := pki.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(cfg.Edge.Cert, cfg.Edge.Key)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	host, _, err := net.SplitHostPort(cfg.Edge.Address)
	if err != nil {
		return nil, fmt.Errorf("edge.address %q: %w", cfg.Edge.Address, err)
	}
	entries := make([]route.Entry[string], 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		entries = append(entries, route.Entry[string]{Pattern: r.Host, Value: r.Service})
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
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			a.drainStreams()
			_ = session.Close()
		case <-stop:
		}
	}()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return time.Since(connectedAt) >= minBackoff, fmt.Errorf("accept stream: %w", err)
		}
		a.mu.Lock()
		if a.draining {
			a.mu.Unlock()
			_ = stream.Close()
			continue
		}
		a.inflight.Add(1)
		a.mu.Unlock()
		go func() {
			defer a.inflight.Done()
			a.handleStream(stream)
		}()
	}
}

func (a *Agent) handleStream(stream net.Conn) {
	defer stream.Close()
	p, err := tunnel.ReadPreamble(stream)
	if err != nil {
		a.log.Warn("stream.preamble_error", "error", err.Error())
		return
	}
	log := a.log.With("conn_id", p.ConnID, "client_addr", p.ClientAddr, "host", p.Host)
	if p.EdgeVersion != a.version {
		// Warn once per process on an edge/agent version skew (an empty
		// EdgeVersion means the edge predates this field, i.e. an older build).
		a.versionWarn.Do(func() {
			log.Warn("version.mismatch", "edge_version", p.EdgeVersion, "agent_version", a.version)
		})
	}
	svcAddr, ok := a.routes.Match(p.Host)
	if !ok {
		log.Warn("stream.no_route", "host", p.Host)
		errpage.Write(stream, 502, "Bad Gateway", "No backend for host", p.ConnID)
		return
	}
	log.Debug("stream.accept")
	svc, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", svcAddr)
	if err != nil {
		log.Error("service.dial_error", "address", svcAddr, "error", err.Error())
		errpage.Write(stream, 502, "Bad Gateway", "Backend unreachable", p.ConnID)
		return
	}
	a.state.StreamOpened()
	log.Debug("service.dial", "address", svcAddr)
	in, out, _ := proxy.Pipe(stream, svc)
	a.state.StreamClosed(in, out)
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
