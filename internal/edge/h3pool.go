package edge

import (
	"context"
	"net"
	"sync"
	"time"
)

// HTTP/3 stream reuse.
//
// Over TCP a client connection is one tunnel stream, and so one backend
// connection, which carries every request the client sends on it. Over
// HTTP/3 each request arrives on its own QUIC stream; giving each its own
// tunnel stream would cost every request a round trip to the agent (its
// accept) and a backend dial. Instead a request's tunnel stream outlives it:
// once the response has ended cleanly, the stream waits in its HTTP/3
// connection's pool and carries that connection's next request for the same
// host, the backend keeping its connection alive in between.
//
// A stream is never shared between HTTP/3 connections, so a backend
// connection only ever carries one client's requests, as over TCP: a service
// that ties state to its connection (a sign-in, say) never sees another
// client's request on it.

// tunnelStream is a tunnel stream serving HTTP/3 requests, and what it holds
// while open: a slot of its route's connection cap, its share of its agent
// session's stream count, and its route's stream gauge. close releases them
// all, once.
type tunnelStream struct {
	e     *Edge
	s     net.Conn
	agent *agentConn
	rs    *routeState
	host  string
	once  sync.Once
}

func (t *tunnelStream) close() {
	t.once.Do(func() {
		abort(t.s)
		t.agent.stat.StreamClosed()
		t.e.state.StreamClosed(t.rs.stats)
		t.rs.sem.release()
	})
}

// h3Pool holds the idle tunnel streams of every HTTP/3 connection. A nil
// *h3Pool keeps nothing.
type h3Pool struct {
	mu     sync.Mutex
	all    map[*idleStream]struct{}
	closed bool // the edge is draining: streams are no longer kept
}

func newH3Pool() *h3Pool {
	return &h3Pool{all: map[*idleStream]struct{}{}}
}

// connStreams is one HTTP/3 connection's idle streams, by host, the most
// recently used last. Guarded by h3Pool.mu.
type connStreams struct {
	idle   map[string][]*idleStream
	n      int
	closed bool // the connection has ended
}

type connStreamsKey struct{}

// connStreamsOf returns the pool of r's HTTP/3 connection, or nil.
func connStreamsOf(r interface{ Context() context.Context }) *connStreams {
	cs, _ := r.Context().Value(connStreamsKey{}).(*connStreams)
	return cs
}

// idleStream is a stream waiting in a connection's pool. While it waits, a
// watcher reads from it: the backend ending its connection (or sending
// anything unasked) ends the read, and the stream is dropped at once rather
// than handed to a request.
type idleStream struct {
	ts    *tunnelStream
	cs    *connStreams
	taken bool          // out of the pool (taken for a request, or closed); guarded by h3Pool.mu
	done  chan struct{} // closed once the watcher has returned
	live  bool          // set by the watcher: its read was ended by take, with nothing read
}

// newConn starts the pool of a new HTTP/3 connection; its streams are closed
// when gone ends.
func (p *h3Pool) newConn(gone context.Context) *connStreams {
	if p == nil {
		return nil
	}
	cs := &connStreams{idle: map[string][]*idleStream{}}
	context.AfterFunc(gone, func() { p.closeConn(cs) })
	return cs
}

// put keeps ts in cs's pool for up to keep, or closes it when it cannot be
// kept: the edge or the connection is closing, the connection already keeps
// its share, the agent is draining, or a request is waiting for a slot of the
// route's connection cap (the slot ts holds goes to it).
func (p *h3Pool) put(cs *connStreams, ts *tunnelStream, keep time.Duration) {
	if p == nil {
		ts.close()
		return
	}
	p.mu.Lock()
	if p.closed || cs.closed || cs.n >= maxKeptPerConn || ts.rs.slotWaiters.Load() > 0 || ts.agent.isRetired() {
		p.mu.Unlock()
		ts.close()
		return
	}
	is := &idleStream{ts: ts, cs: cs, done: make(chan struct{})}
	cs.idle[ts.host] = append(cs.idle[ts.host], is)
	cs.n++
	p.all[is] = struct{}{}
	// Set before the watcher starts, under the lock, so a take (which needs
	// the lock to find it) always overrides it.
	_ = ts.s.SetWriteDeadline(time.Time{})
	_ = ts.s.SetReadDeadline(time.Now().Add(keep))
	p.mu.Unlock()
	go p.watch(is)
}

func (p *h3Pool) watch(is *idleStream) {
	var b [1]byte
	n, err := is.ts.s.Read(b[:])
	p.mu.Lock()
	taken := is.taken
	if !taken {
		p.removeLocked(is) // closed by the backend, sent something unasked, or idle too long
	}
	is.live = taken && n == 0 && isTimeout(err)
	p.mu.Unlock()
	close(is.done)
	if !taken {
		is.ts.close()
	}
}

// take returns a stream from cs's pool for a request to host on rs, or nil.
// A stream whose agent has started draining meanwhile is closed, not used.
func (p *h3Pool) take(cs *connStreams, host string, rs *routeState) *tunnelStream {
	if p == nil {
		return nil
	}
	for {
		p.mu.Lock()
		list := cs.idle[host]
		if len(list) == 0 {
			p.mu.Unlock()
			return nil
		}
		is := list[len(list)-1]
		p.removeLocked(is)
		p.mu.Unlock()
		_ = is.ts.s.SetReadDeadline(time.Now()) // end the watcher's read
		<-is.done
		if is.live && is.ts.rs == rs && !is.ts.agent.sess.IsClosed() && !is.ts.agent.isRetired() {
			_ = is.ts.s.SetReadDeadline(time.Time{})
			return is.ts
		}
		is.ts.close() // it ended while it waited
	}
}

// removeLocked takes is out of the pool. Callers hold p.mu.
func (p *h3Pool) removeLocked(is *idleStream) {
	if is.taken {
		return
	}
	is.taken = true
	list := is.cs.idle[is.ts.host]
	for i, o := range list {
		if o == is {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(is.cs.idle, is.ts.host)
	} else {
		is.cs.idle[is.ts.host] = list
	}
	is.cs.n--
	delete(p.all, is)
}

// removeWhereLocked takes every idle stream for which match holds out of the
// pool, for the caller to close once it has released p.mu.
func (p *h3Pool) removeWhereLocked(match func(*idleStream) bool) []*idleStream {
	var out []*idleStream
	for is := range p.all {
		if match(is) {
			p.removeLocked(is)
			out = append(out, is)
		}
	}
	return out
}

// closeIdle closes streams taken out of the pool; each watcher then returns,
// finding its stream taken.
func closeIdle(list []*idleStream) {
	for _, is := range list {
		is.ts.close()
	}
}

// closeConn closes cs's idle streams and keeps no more: its connection has
// ended.
func (p *h3Pool) closeConn(cs *connStreams) {
	p.mu.Lock()
	cs.closed = true
	gone := p.removeWhereLocked(func(is *idleStream) bool { return is.cs == cs })
	p.mu.Unlock()
	closeIdle(gone)
}

// closeAgent closes the idle streams on c's session: the agent is draining,
// and a stream kept for a later request would hold up its drain.
func (p *h3Pool) closeAgent(c *agentConn) {
	if p == nil {
		return
	}
	p.mu.Lock()
	gone := p.removeWhereLocked(func(is *idleStream) bool { return is.ts.agent == c })
	p.mu.Unlock()
	closeIdle(gone)
}

// closeAll closes every idle stream and keeps no more: the edge is draining.
func (p *h3Pool) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	gone := p.removeWhereLocked(func(*idleStream) bool { return true })
	p.mu.Unlock()
	closeIdle(gone)
}

// evictRoute closes one idle stream on rs, freeing its slot of the route's
// connection cap for a request that needs one, and reports whether there was
// one.
func (p *h3Pool) evictRoute(rs *routeState) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	var victim *idleStream
	for is := range p.all {
		if is.ts.rs == rs {
			victim = is
			break
		}
	}
	if victim != nil {
		p.removeLocked(victim)
	}
	p.mu.Unlock()
	if victim == nil {
		return false
	}
	victim.ts.close()
	return true
}
