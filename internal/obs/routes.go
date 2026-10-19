package obs

import (
	"sort"
	"sync/atomic"
	"time"
)

// Reason is why a request or stream could not be served. Reasons are metric
// label values, so the set is fixed in code.
type Reason uint8

const (
	ReasonMaxConnections      Reason = iota // edge: global connection cap
	ReasonBadRequest                        // edge: malformed or slow request head
	ReasonNoRoute                           // edge or agent: no route matched the host
	ReasonRouteMaxConnections               // edge: per-route connection cap
	ReasonNoAgent                           // edge: the route's agent is offline
	ReasonStreamError                       // edge: tunnel stream could not be opened or set up
	ReasonPreambleError                     // agent: stream preamble unreadable
	ReasonDialError                         // agent: backend unreachable
	ReasonResponseTimeout                   // edge: no response within idle_timeout (HTTP/3)
	ReasonBadResponse                       // edge: the service's response could not be relayed (HTTP/3)
	ReasonHTTP3Off                          // edge: HTTP/3 for a route kept off it (routes[].http3: false)
	numReasons
)

var reasonNames = [numReasons]string{
	ReasonMaxConnections:      "max_connections",
	ReasonBadRequest:          "bad_request",
	ReasonNoRoute:             "no_route",
	ReasonRouteMaxConnections: "route_max_connections",
	ReasonNoAgent:             "no_agent",
	ReasonStreamError:         "stream_error",
	ReasonPreambleError:       "preamble_error",
	ReasonDialError:           "dial_error",
	ReasonResponseTimeout:     "response_timeout",
	ReasonBadResponse:         "bad_response",
	ReasonHTTP3Off:            "http3_off",
}

// String returns the reason's metric label value.
func (r Reason) String() string {
	if r < numReasons {
		return reasonNames[r]
	}
	return "unknown"
}

// Which reasons each role records, before a route is known (unrouted) and on a
// matched route. The metrics endpoint reports every listed reason from zero,
// and any other reason once it is non-zero.
var (
	EdgeUnroutedReasons  = []Reason{ReasonMaxConnections, ReasonBadRequest, ReasonNoRoute}
	EdgeRouteReasons     = []Reason{ReasonRouteMaxConnections, ReasonNoAgent, ReasonStreamError, ReasonResponseTimeout, ReasonBadResponse, ReasonHTTP3Off}
	AgentUnroutedReasons = []Reason{ReasonPreambleError, ReasonNoRoute}
	AgentRouteReasons    = []Reason{ReasonDialError}
)

// reasonCounts is one lock-free counter per Reason.
type reasonCounts [numReasons]atomic.Int64

func (c *reasonCounts) inc(r Reason) {
	if r < numReasons {
		c[r].Add(1)
	}
}

// ReasonCounts is a point-in-time copy of one count per Reason.
type ReasonCounts [numReasons]int64

// Get returns the count for r, or 0 for an out-of-range reason.
func (c ReasonCounts) Get(r Reason) int64 {
	if r < numReasons {
		return c[r]
	}
	return 0
}

func (c *reasonCounts) snapshot() ReasonCounts {
	var out ReasonCounts
	for r := range out {
		out[r] = c[r].Load()
	}
	return out
}

// RouteStats holds the live counters for one configured route, keyed by its
// host pattern. Routes are registered once at startup, so the number of
// RouteStats (and thus metric label values) is bounded by configuration, never
// by traffic. All methods are safe on a nil receiver and then do nothing, so a
// route built without stats still works.
type RouteStats struct {
	pattern  string
	active   atomic.Int64
	total    atomic.Int64 // all streams
	totalH3  atomic.Int64 // edge: of which for HTTP/3 requests
	reqH3    atomic.Int64 // edge: HTTP/3 requests sent to the service, over those streams
	waits    atomic.Int64 // edge: requests that waited for an agent (see AgentWait)
	bytes    [byteShards]byteShard
	next     atomic.Uint32 // round-robin shard assignment for new streams
	failures reasonCounts
}

func (r *RouteStats) opened(http3 bool) {
	if r == nil {
		return
	}
	r.active.Add(1)
	r.total.Add(1)
	if http3 {
		r.totalH3.Add(1) // after total, so a snapshot never sees more HTTP/3 streams than streams
	}
}

// HTTP3Request counts an HTTP/3 request sent to the service. A stream for
// HTTP/3 requests carries one or more of a connection's requests in turn.
func (r *RouteStats) HTTP3Request() {
	if r == nil {
		return
	}
	r.reqH3.Add(1)
}

// AgentWait counts a request that found no agent to take it and waited for
// one (agent_wait), whether one came or not.
func (r *RouteStats) AgentWait() {
	if r == nil {
		return
	}
	r.waits.Add(1)
}

func (r *RouteStats) closed() {
	if r == nil {
		return
	}
	r.active.Add(-1)
}

// byteShards spreads a route's byte counters over separate cache lines, so
// concurrent streams on one route rarely contend on the same counter. Each
// stream counts every write at once (live), on its own shard.
const byteShards = 16

// byteShard is one stream group's byte counters, padded to its own cache line.
type byteShard struct {
	in, out atomic.Int64
	_       [48]byte
}

// StreamBytes counts the bytes of one open stream on a route. AddIn and AddOut
// are called on every write in the data path.
type StreamBytes struct{ shard *byteShard }

// AddIn counts n bytes carried client-to-backend.
func (b StreamBytes) AddIn(n int64) {
	if b.shard != nil {
		b.shard.in.Add(n)
	}
}

// AddOut counts n bytes carried backend-to-client.
func (b StreamBytes) AddOut(n int64) {
	if b.shard != nil {
		b.shard.out.Add(n)
	}
}

// Bytes returns the byte counter for a new stream on this route. A nil route
// returns a counter that counts nothing.
func (r *RouteStats) Bytes() StreamBytes {
	if r == nil {
		return StreamBytes{}
	}
	return StreamBytes{shard: &r.bytes[r.next.Add(1)%byteShards]}
}

// byteTotals sums the shards.
func (r *RouteStats) byteTotals() (in, out int64) {
	for i := range r.bytes {
		in += r.bytes[i].in.Load()
		out += r.bytes[i].out.Load()
	}
	return in, out
}

// Failure counts a request on this route that could not be served, by reason.
func (r *RouteStats) Failure(reason Reason) {
	if r == nil {
		return
	}
	r.failures.inc(reason)
}

// RouteSnapshot is a point-in-time copy of one route's counters.
type RouteSnapshot struct {
	Pattern  string
	Active   int64
	Total    int64 // all streams
	TotalH3  int64 // of which for HTTP/3 requests (edge)
	ReqH3    int64 // HTTP/3 requests sent over them (edge)
	Waits    int64 // requests that waited for an agent (edge)
	BytesIn  int64
	BytesOut int64
	Failures ReasonCounts
}

// Route returns the stats for pattern, creating them on first use. The edge and
// agent call it once per configured route at startup.
func (s *State) Route(pattern string) *RouteStats {
	s.routesMu.Lock()
	defer s.routesMu.Unlock()
	if s.routes == nil {
		s.routes = make(map[string]*RouteStats)
	}
	if r, ok := s.routes[pattern]; ok {
		return r
	}
	r := &RouteStats{pattern: pattern}
	s.routes[pattern] = r
	return r
}

// Failure counts a request that failed before it could be attributed to a
// route (for example a malformed request, or a host with no route).
func (s *State) Failure(reason Reason) { s.unrouted.inc(reason) }

// ExpectAgents records the agent fingerprints the configuration allows, so
// metrics can report an offline agent as disconnected (0) rather than omit it.
func (s *State) ExpectAgents(allowed map[string]bool) {
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	if s.expected == nil {
		s.expected = make(map[string]bool, len(allowed))
	}
	for fp, ok := range allowed {
		if ok {
			s.expected[fp] = true
		}
	}
}

// HeaderTimeout counts an ingress connection closed at the read-header deadline
// without having sent any request byte (an idle preconnect or an idle-
// connection flood). It is not a rejected request: nothing was asked.
func (s *State) HeaderTimeout() { s.headerTimeouts.Add(1) }

// Detail is the full metrics view of a State: the status Snapshot plus the
// per-route counters, unrouted failures, expected agents, and start time.
type Detail struct {
	Snapshot
	Routes           []RouteSnapshot // sorted by pattern
	UnroutedFailures ReasonCounts
	HeaderTimeouts   int64
	Draining         bool
	ExpectedAgents   []string         // sorted
	AgentStreams     map[string]int64 // streams opened per fingerprint, ever
	StartTime        time.Time
}

// routeSnapshots copies every route's counters once, sorted by pattern.
func (s *State) routeSnapshots() []RouteSnapshot {
	s.routesMu.Lock()
	out := make([]RouteSnapshot, 0, len(s.routes))
	for _, r := range s.routes {
		in, outB := r.byteTotals()
		h3 := r.totalH3.Load() // before total (see opened)
		all := r.total.Load()
		out = append(out, RouteSnapshot{
			Pattern:  r.pattern,
			Active:   r.active.Load(),
			Total:    all,
			TotalH3:  h3,
			ReqH3:    r.reqH3.Load(),
			Waits:    r.waits.Load(),
			BytesIn:  in,
			BytesOut: outB,
			Failures: r.failures.snapshot(),
		})
	}
	s.routesMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

// Detail returns a copy of every counter for a metrics scrape. Counters are
// read individually (atomically), not under one global lock; the routes are
// read once, so the byte totals agree with the per-route bytes.
func (s *State) Detail() Detail {
	routes := s.routeSnapshots()
	d := Detail{Snapshot: s.snapshot(routes), Routes: routes, UnroutedFailures: s.unrouted.snapshot(), HeaderTimeouts: s.headerTimeouts.Load(), Draining: s.draining.Load(), StartTime: s.started}
	s.agentsMu.Lock()
	for fp := range s.expected {
		d.ExpectedAgents = append(d.ExpectedAgents, fp)
	}
	d.AgentStreams = make(map[string]int64, len(s.agentTotals))
	for fp, n := range s.agentTotals {
		d.AgentStreams[fp] = n.Load()
	}
	s.agentsMu.Unlock()
	sort.Strings(d.ExpectedAgents)
	return d
}
