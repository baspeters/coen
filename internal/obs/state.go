package obs

import (
	"sync"
	"sync/atomic"
	"time"
)

// State holds live counters shared between the running daemon and the admin socket.
type State struct {
	role          string // "edge" or "agent"; tags snapshots so status renders per role
	connected     atomic.Bool
	connectedNano atomic.Int64
	activeStreams atomic.Int64
	totalStreams  atomic.Int64
	maxStreams    atomic.Int64 // high-water mark of concurrent streams
	bytesIn       atomic.Int64
	bytesOut      atomic.Int64
	reconnects    atomic.Int64
	handshakeOK   atomic.Int64
	handshakeFail atomic.Int64
	lastError     atomic.Value // string
	peerFP        atomic.Value // string

	agentsMu sync.Mutex
	agents   map[string]agentEntry // edge: connected agents by fingerprint
}

// agentEntry is the per-agent info the edge tracks for a connected tunnel.
type agentEntry struct {
	since time.Time
	addr  string
}

// NewState returns a State tagged with the daemon's role ("edge" or "agent").
func NewState(role string) *State { return &State{role: role} }

// AgentConnected records a live edge<-agent tunnel keyed by fingerprint, with
// the agent's remote address.
func (s *State) AgentConnected(fp, addr string) {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	if s.agents == nil {
		s.agents = make(map[string]agentEntry)
	}
	s.agents[fp] = agentEntry{since: time.Now(), addr: addr}
}

// AgentDisconnected removes a tunnel.
func (s *State) AgentDisconnected(fp string) {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	delete(s.agents, fp)
}

// AgentInfo describes one connected agent in a Snapshot.
type AgentInfo struct {
	Fingerprint    string    `json:"fingerprint"`
	RemoteAddr     string    `json:"remote_addr,omitempty"`
	ConnectedSince time.Time `json:"connected_since"`
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
func (s *State) StreamOpened() {
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
func (s *State) StreamClosed(in, out int64) {
	s.activeStreams.Add(-1)
	s.bytesIn.Add(in)
	s.bytesOut.Add(out)
}
func (s *State) Reconnect()        { s.reconnects.Add(1) }
func (s *State) HandshakeOK()      { s.handshakeOK.Add(1) }
func (s *State) HandshakeFail()    { s.handshakeFail.Add(1) }
func (s *State) SetError(e string) { s.lastError.Store(e) }

type Snapshot struct {
	Role            string      `json:"role,omitempty"`
	TunnelConnected bool        `json:"tunnel_connected"`
	ConnectedSince  time.Time   `json:"connected_since,omitzero"`
	ActiveStreams   int64       `json:"active_streams"`
	MaxStreams      int64       `json:"max_streams"`
	TotalStreams    int64       `json:"total_streams"`
	BytesIn         int64       `json:"bytes_in"`
	BytesOut        int64       `json:"bytes_out"`
	Reconnects      int64       `json:"reconnects"`
	HandshakeOK     int64       `json:"handshake_ok"`
	HandshakeFail   int64       `json:"handshake_fail"`
	LastError       string      `json:"last_error,omitempty"`
	PeerFingerprint string      `json:"peer_fingerprint,omitempty"`
	Agents          []AgentInfo `json:"agents,omitempty"`
}

func loadStr(v *atomic.Value) string {
	if x := v.Load(); x != nil {
		return x.(string)
	}
	return ""
}

func (s *State) Snapshot() Snapshot {
	snap := Snapshot{
		Role:            s.role,
		TunnelConnected: s.connected.Load(),
		ActiveStreams:   s.activeStreams.Load(),
		MaxStreams:      s.maxStreams.Load(),
		TotalStreams:    s.totalStreams.Load(),
		BytesIn:         s.bytesIn.Load(),
		BytesOut:        s.bytesOut.Load(),
		Reconnects:      s.reconnects.Load(),
		HandshakeOK:     s.handshakeOK.Load(),
		HandshakeFail:   s.handshakeFail.Load(),
		LastError:       loadStr(&s.lastError),
		PeerFingerprint: loadStr(&s.peerFP),
	}
	if snap.TunnelConnected {
		snap.ConnectedSince = time.Unix(0, s.connectedNano.Load())
	}
	s.agentsMu.Lock()
	for fp, e := range s.agents {
		snap.Agents = append(snap.Agents, AgentInfo{Fingerprint: fp, RemoteAddr: e.addr, ConnectedSince: e.since})
	}
	s.agentsMu.Unlock()
	return snap
}
