package edge

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/baspeters/coen/internal/obs"
	"github.com/hashicorp/yamux"
)

// agentConn is one agent tunnel: its fingerprint, session, stream accounting,
// and whether it has been retired (taken out of the pool while it drains).
type agentConn struct {
	fp   string
	sess *yamux.Session
	stat *obs.AgentSession // nil-safe; nil in tests that seed the registry directly
	v2   bool              // the agent negotiated tunnel.ALPNv2 (sends accept bytes)

	// mu guards retired and opening. A stream is opened only while the
	// session is not retired, counted in opening; retire marks the session
	// and then waits (bounded) for opening to reach zero, so once it returns
	// every stream opened on the session has already been sent to the agent.
	// Picks never wait on retire.
	mu      sync.Mutex
	idle    chan struct{} // closed when opening drops to zero after a retire waits
	retired bool
	opening int
	// coolUntil (unix nanos) keeps a session that just failed to set up a
	// stream, while still open, out of picks for a moment (see coolDown).
	coolUntil atomic.Int64
	// stuck counts opens given up on that are still blocked in yamux (see
	// openUnlessRetired); guarded by mu.
	stuck int
}

// isRetired reports whether c has been taken out of the pool to drain.
func (c *agentConn) isRetired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.retired
}

// liveOpensLocked counts opens in flight that may still reach the agent with
// a request: those not given up on (an abandoned open's stream is closed
// unused). Callers hold mu.
func (c *agentConn) liveOpensLocked() int { return c.opening - c.stuck }

// wakeIfIdleLocked wakes a retireForDrain waiting for the live opens once
// there are none. Callers hold mu.
func (c *agentConn) wakeIfIdleLocked() {
	if c.liveOpensLocked() <= 0 && c.idle != nil {
		close(c.idle)
		c.idle = nil
	}
}

// coolDownFor keeps c out of picks for d (unless it is the only option),
// never shortening a longer cooldown already in place.
func (c *agentConn) coolDownFor(d time.Duration) {
	until := time.Now().Add(d).UnixNano()
	for {
		cur := c.coolUntil.Load()
		if cur >= until || c.coolUntil.CompareAndSwap(cur, until) {
			return
		}
	}
}

// registry maps an agent client-cert fingerprint to its live tunnel sessions
// (the pool the balancer picks from). Most fingerprints have at most one
// session; a fingerprint listed in shared (allow_shared_cert) may have several,
// one per agent running that certificate. all holds every session until it
// closes, including retired ones, so shutdown can close them all.
type registry struct {
	mu      sync.RWMutex
	byFP    map[string][]*agentConn
	all     map[*yamux.Session]*tracked // every open session, pooled or retired
	joined  map[string]int              // per fingerprint: open sessions that were pooled
	pending map[string]int              // per fingerprint: open sessions not (yet) pooled
	shared  map[string]bool
	closing bool // closeAll has run: no new session is tracked or pooled
	// joinedCh is closed (and replaced) each time a session joins the pool,
	// waking requests that wait for an agent (see Edge.dispatch).
	joinedCh chan struct{}
}

func newRegistry() *registry {
	return &registry{byFP: make(map[string][]*agentConn), all: make(map[*yamux.Session]*tracked), joined: make(map[string]int), pending: make(map[string]int), shared: map[string]bool{}, joinedCh: make(chan struct{})}
}

// joins returns a channel closed when the next session joins the pool. Take
// it before looking for a session, so one that joins in between is not
// missed.
func (r *registry) joins() <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.joinedCh
}

// tracked is the registry's record of one open session.
type tracked struct {
	fp     string
	joined bool // it was pooled (and may since have been retired)
}

// registration is why registerConn did or did not pool a session.
type registration int

const (
	registered       registration = iota
	refusedDuplicate              // fp already has a live session and is not shared
	refusedCap                    // fp has maxSharedSessions open sessions
	refusedGone                   // shutting down, or the newcomer is already closed
)

// registerConn adds c to the pool for fp and, when it does, also returns how
// many sessions fp now has in the pool. Sessions for fp that have already
// closed are dropped first (their own serveAgent records the disconnect).
// Unless fp may be shared, a fingerprint that still has a live session keeps
// it and the newcomer is refused. This stops a serving agent from being
// displaced by a duplicate certificate; a genuine reconnect is unaffected
// because the old session is already closed by then. c.fp must already be fp,
// and c.sess tracked (see track).
func (r *registry) registerConn(fp string, c *agentConn) (registration, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	live := r.liveLocked(fp)
	switch {
	case r.closing || c.sess.IsClosed():
		return refusedGone, 0
	case r.duplicateLocked(fp, live):
		return refusedDuplicate, 0
	case r.joined[fp] >= maxSharedSessions:
		// Counts retired sessions too: one that drains but never closes
		// still holds edge resources. Sessions still connecting are capped
		// separately (see track), so a burst of reconnects is not refused.
		return refusedCap, 0
	}
	r.byFP[fp] = append(live, c)
	close(r.joinedCh)
	r.joinedCh = make(chan struct{})
	if t := r.all[c.sess]; t != nil && !t.joined {
		t.joined = true
		r.joined[fp]++
		r.unpendLocked(fp)
	}
	return registered, len(r.byFP[fp])
}

// liveLocked drops fp's pooled sessions that have closed and returns the rest.
func (r *registry) liveLocked(fp string) []*agentConn {
	conns := r.byFP[fp]
	live := conns[:0:0]
	for _, cur := range conns {
		if !cur.sess.IsClosed() {
			live = append(live, cur)
		}
	}
	switch {
	case len(live) == len(conns):
		return conns // nothing dropped: leave the map as it is
	case len(live) == 0:
		delete(r.byFP, fp)
	default:
		r.byFP[fp] = live
	}
	return live
}

// hasLiveExclusive reports whether a new connection with fp would be refused
// as a duplicate: fp is not shared and already has a live pooled session. It
// is the same rule registerConn applies.
func (r *registry) hasLiveExclusive(fp string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.duplicateLocked(fp, r.liveLocked(fp))
}

// duplicateLocked is the duplicate rule: a newcomer for fp is refused while
// fp, not shared, already has a live session (live, from liveLocked).
func (r *registry) duplicateLocked(fp string, live []*agentConn) bool {
	return !r.shared[fp] && len(live) > 0
}

// maxSharedSessions caps, per fingerprint, both the pooled sessions and,
// separately, the sessions still connecting, so a leaked certificate holds at
// most twice this many sessions on the edge.
const maxSharedSessions = 256

// trackResult is whether track recorded a session.
type trackResult int

const (
	trackOK      trackResult = iota
	trackClosing             // closeAll has run
	trackCapped              // fp has maxSharedSessions sessions still connecting
)

// track records a session of fingerprint fp as soon as it exists, before it
// is pooled, so a shutdown in between still closes it. Unless it reports
// trackOK the session is not recorded and the caller closes it itself.
func (r *registry) track(fp string, s *yamux.Session) trackResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.closing:
		return trackClosing
	case r.pending[fp] >= maxSharedSessions:
		return trackCapped
	}
	r.all[s] = &tracked{fp: fp}
	r.pending[fp]++
	return trackOK
}

func (r *registry) unpendLocked(fp string) {
	if r.pending[fp]--; r.pending[fp] <= 0 {
		delete(r.pending, fp)
	}
}

// drop removes a closed session from the pool and from the tracked set, under
// one lock.
func (r *registry) drop(s *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.all[s]; t != nil {
		r.removeLocked(t.fp, s)
		if t.joined {
			if r.joined[t.fp]--; r.joined[t.fp] <= 0 {
				delete(r.joined, t.fp)
			}
		} else {
			r.unpendLocked(t.fp)
		}
		delete(r.all, s)
	}
}

// candidates returns the pooled sessions of the given fingerprints that are
// still open, in the order the fingerprints are listed and, per fingerprint,
// in registration order, and separately the pooled sessions that have already
// closed, so the caller can evict them at once.
func (r *registry) candidates(fps []string) (live, dead []*agentConn) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, fp := range fps {
		for _, c := range r.byFP[fp] {
			if c.sess.IsClosed() {
				dead = append(dead, c)
			} else {
				live = append(live, c)
			}
		}
	}
	return live, dead
}

// take removes s from fp's pool, if it is still there (it may already have
// been removed, for example by a concurrent eviction).
func (r *registry) take(fp string, s *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(fp, s)
}

// removeLocked removes s from fp's pool, if it is there.
func (r *registry) removeLocked(fp string, s *yamux.Session) {
	conns := r.byFP[fp]
	for i, c := range conns {
		if c.sess == s {
			conns = append(conns[:i:i], conns[i+1:]...)
			if len(conns) == 0 {
				delete(r.byFP, fp)
			} else {
				r.byFP[fp] = conns
			}
			return
		}
	}
}

// closeAll closes every session, pooled or retired. Each serveAgent goroutine
// then cleans up its own entry when its CloseChan fires.
func (r *registry) closeAll() {
	r.mu.Lock()
	r.closing = true
	sessions := make([]*yamux.Session, 0, len(r.all))
	for s := range r.all {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	// Close outside the lock and in parallel: each Close can wait on a slow
	// peer, and the sessions' own goroutines need the lock to clean up.
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Close() }()
	}
	wg.Wait()
}
