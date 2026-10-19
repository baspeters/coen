package obs

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// State holds live counters shared between the running daemon and the admin socket.
type State struct {
	role              string // "edge" or "agent"; tags snapshots so status renders per role
	connected         atomic.Bool
	connectedNano     atomic.Int64
	activeStreams     atomic.Int64
	totalStreams      atomic.Int64
	maxStreams        atomic.Int64 // high-water mark of concurrent streams
	reconnects        atomic.Int64
	handshakeOK       atomic.Int64
	handshakeFail     atomic.Int64
	handshakeRejected atomic.Int64 // edge: unauthenticated/incompatible peers refused at TLS
	handshakeDup      atomic.Int64 // edge: authenticated agents refused as a duplicate fingerprint
	handshakeCapped   atomic.Int64 // edge: agents refused at the per-certificate session cap
	lastError         atomic.Value // string
	peerFP            atomic.Value // string
	selfFP            atomic.Value // string: this daemon's own certificate fingerprint

	agentsMu    sync.Mutex
	agents      map[*AgentSession]struct{} // edge: connected agent sessions (several may share a fingerprint)
	expected    map[string]bool            // edge: agent fingerprints the config allows
	agentTotals map[string]*atomic.Int64   // edge: streams opened per fingerprint, ever

	routesMu       sync.Mutex
	routes         map[string]*RouteStats // per configured route pattern
	unrouted       reasonCounts           // failures not attributable to a route
	headerTimeouts atomic.Int64           // edge: idle connections cut off at the read-header deadline
	draining       atomic.Bool            // shutdown has started; in-flight streams are draining
	started        time.Time
}

// AgentSession is one connected agent tunnel on the edge. Several sessions may
// share a fingerprint (load-balanced agents with a shared certificate). Its
// methods are safe on a nil receiver.
type AgentSession struct {
	fp       string
	addr     string
	since    time.Time
	active   atomic.Int64
	total    *atomic.Int64 // the fingerprint's lifetime stream counter
	draining atomic.Bool   // out of the edge's pool; in-flight streams finishing
}

// Active returns the session's open streams, used to balance by least
// connections.
func (a *AgentSession) Active() int64 {
	if a == nil {
		return 0
	}
	return a.active.Load()
}

// Reserve counts a stream as open while it is being set up, so concurrent
// least_conn picks see it. Follow with Commit once it is set up, or with
// StreamClosed if it could not be.
func (a *AgentSession) Reserve() {
	if a != nil {
		a.active.Add(1)
	}
}

// Commit adds a reserved stream to the session's lifetime total. The total
// only ever grows, as a Prometheus counter must.
func (a *AgentSession) Commit() {
	if a != nil {
		a.total.Add(1)
	}
}

// StreamClosed counts a stream on this session that ended.
func (a *AgentSession) StreamClosed() {
	if a != nil {
		a.active.Add(-1)
	}
}

// SetDraining marks the session as taken out of the pool while its in-flight
// streams finish.
func (a *AgentSession) SetDraining() {
	if a != nil {
		a.draining.Store(true)
	}
}

// SetDraining records that shutdown has started. A starting replacement reads
// it (through the metrics endpoint) to tell a draining predecessor from a
// second live instance holding the same port.
func (s *State) SetDraining() { s.draining.Store(true) }

// Role returns the daemon role this State was created with.
func (s *State) Role() string { return s.role }

// NewState returns a State tagged with the daemon's role ("edge" or "agent").
func NewState(role string) *State { return &State{role: role, started: time.Now()} }

// NewAgentSession prepares the accounting for an agent session of fingerprint
// fp from addr without listing it as connected; AddAgent lists it once the
// edge has accepted it.
func (s *State) NewAgentSession(fp, addr string) *AgentSession {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	if s.agentTotals == nil {
		s.agentTotals = make(map[string]*atomic.Int64)
	}
	total := s.agentTotals[fp]
	if total == nil {
		total = new(atomic.Int64)
		s.agentTotals[fp] = total
	}
	return &AgentSession{fp: fp, addr: addr, since: time.Now(), total: total}
}

// AddAgent lists a prepared session as connected.
func (s *State) AddAgent(a *AgentSession) {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	if s.agents == nil {
		s.agents = make(map[*AgentSession]struct{})
	}
	s.agents[a] = struct{}{}
}

// AgentDisconnected removes a session; calling it again is harmless.
func (s *State) AgentDisconnected(a *AgentSession) {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	delete(s.agents, a)
}

// AgentInfo describes one connected agent session in a Snapshot.
type AgentInfo struct {
	Fingerprint    string    `json:"fingerprint"`
	RemoteAddr     string    `json:"remote_addr,omitempty"`
	ConnectedSince time.Time `json:"connected_since"`
	ActiveStreams  int64     `json:"active_streams"`
	Draining       bool      `json:"draining,omitempty"`
}

func (s *State) SetConnected(fp string) {
	// Store the details before flipping connected, so a concurrent Snapshot
	// never observes connected=true with a not-yet-written since (epoch) or fp.
	s.connectedNano.Store(time.Now().UnixNano())
	s.peerFP.Store(fp)
	s.connected.Store(true)
}
func (s *State) SetDisconnected() {
	s.connected.Store(false)
	s.peerFP.Store("") // don't report a stale peer fingerprint once disconnected
}

// StreamOpened counts a newly opened stream, globally and, when r is non-nil,
// on its route. One call records both, so the two views cannot drift apart.
func (s *State) StreamOpened(r *RouteStats) {
	r.opened()
	n := s.activeStreams.Add(1)
	s.totalStreams.Add(1)
	// Raise the concurrency high-water mark if this open set a new peak.
	for {
		m := s.maxStreams.Load()
		if n <= m || s.maxStreams.CompareAndSwap(m, n) {
			break
		}
	}
}

// StreamClosed records that a stream ended, globally and on r when non-nil.
func (s *State) StreamClosed(r *RouteStats) {
	r.closed()
	s.activeStreams.Add(-1)
}
func (s *State) Reconnect()     { s.reconnects.Add(1) }
func (s *State) HandshakeOK()   { s.handshakeOK.Add(1) }
func (s *State) HandshakeFail() { s.handshakeFail.Add(1) }

// HandshakeRejected counts a peer refused at the TLS handshake: it never
// authenticated (no client certificate, or an incompatible TLS version or
// cipher). On a public mTLS port this is routine scanner/probe noise, kept
// separate from HandshakeFail so it does not look like an agent problem.
func (s *State) HandshakeRejected() { s.handshakeRejected.Add(1) }

// HandshakeDuplicate counts an authenticated agent refused because a live
// session already owns its fingerprint (a cloned certificate, or a stray
// reconnect racing the old session).
func (s *State) HandshakeDuplicate() { s.handshakeDup.Add(1) }

// HandshakeCapped counts an agent refused because its (shared) certificate
// already holds the maximum number of sessions.
func (s *State) HandshakeCapped()  { s.handshakeCapped.Add(1) }
func (s *State) SetError(e string) { s.lastError.Store(e) }

// SetSelfFingerprint records this daemon's own certificate fingerprint, set
// once at startup. It lets an operator cross-check the two ends: the agent's
// self_fp equals the fingerprint the edge lists for it, and the edge's self_fp
// equals the agent's peer_fp.
func (s *State) SetSelfFingerprint(fp string) { s.selfFP.Store(fp) }

type Snapshot struct {
	Role              string      `json:"role,omitempty"`
	TunnelConnected   bool        `json:"tunnel_connected"`
	ConnectedSince    time.Time   `json:"connected_since,omitzero"`
	ActiveStreams     int64       `json:"active_streams"`
	MaxStreams        int64       `json:"max_streams"`
	TotalStreams      int64       `json:"total_streams"`
	BytesIn           int64       `json:"bytes_in"`
	BytesOut          int64       `json:"bytes_out"`
	Reconnects        int64       `json:"reconnects"`
	HandshakeOK       int64       `json:"handshake_ok"`
	HandshakeFail     int64       `json:"handshake_fail"`
	HandshakeRejected int64       `json:"handshake_rejected"`
	HandshakeDup      int64       `json:"handshake_duplicate"`
	HandshakeCapped   int64       `json:"handshake_capped"`
	LastError         string      `json:"last_error,omitempty"`
	SelfFingerprint   string      `json:"self_fingerprint,omitempty"`
	PeerFingerprint   string      `json:"peer_fingerprint,omitempty"`
	Agents            []AgentInfo `json:"agents,omitempty"`
}

func loadStr(v *atomic.Value) string {
	if x := v.Load(); x != nil {
		return x.(string)
	}
	return ""
}

// Snapshot returns the status view of the counters.
func (s *State) Snapshot() Snapshot { return s.snapshot(s.routeSnapshots()) }

// snapshot builds a Snapshot, taking byte totals from the given route copies
// (bytes are counted only per route, in the data path).
func (s *State) snapshot(routes []RouteSnapshot) Snapshot {
	snap := Snapshot{
		Role:              s.role,
		TunnelConnected:   s.connected.Load(),
		ActiveStreams:     s.activeStreams.Load(),
		MaxStreams:        s.maxStreams.Load(),
		TotalStreams:      s.totalStreams.Load(),
		Reconnects:        s.reconnects.Load(),
		HandshakeOK:       s.handshakeOK.Load(),
		HandshakeFail:     s.handshakeFail.Load(),
		HandshakeRejected: s.handshakeRejected.Load(),
		HandshakeDup:      s.handshakeDup.Load(),
		HandshakeCapped:   s.handshakeCapped.Load(),
		LastError:         loadStr(&s.lastError),
		SelfFingerprint:   loadStr(&s.selfFP),
		PeerFingerprint:   loadStr(&s.peerFP),
	}
	if snap.TunnelConnected {
		snap.ConnectedSince = time.Unix(0, s.connectedNano.Load())
	}
	for _, r := range routes {
		snap.BytesIn += r.BytesIn
		snap.BytesOut += r.BytesOut
	}
	s.agentsMu.Lock()
	for a := range s.agents {
		snap.Agents = append(snap.Agents, AgentInfo{Fingerprint: a.fp, RemoteAddr: a.addr, ConnectedSince: a.since, ActiveStreams: a.active.Load(), Draining: a.draining.Load()})
	}
	s.agentsMu.Unlock()
	// A stable order: by fingerprint, then by when the session connected.
	sort.Slice(snap.Agents, func(i, j int) bool {
		if snap.Agents[i].Fingerprint != snap.Agents[j].Fingerprint {
			return snap.Agents[i].Fingerprint < snap.Agents[j].Fingerprint
		}
		return snap.Agents[i].ConnectedSince.Before(snap.Agents[j].ConnectedSince)
	})
	return snap
}
