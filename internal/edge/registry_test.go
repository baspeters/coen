package edge

import (
	"net"
	"testing"

	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// newServerSession builds a real edge/agent yamux pair over net.Pipe (no TLS
// needed) and is reused by the edge routing/draining tests.
// set stores s under fp and returns any session it displaced. It is a
// test-only helper for seeding the registry directly; production code uses the
// guarded register instead.
func (r *registry) set(fp string, s *yamux.Session) (prev *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if conns := r.byFP[fp]; len(conns) > 0 {
		prev = conns[0].sess
	}
	r.byFP[fp] = []*agentConn{{fp: fp, sess: s}}
	if r.all[s] == nil {
		r.all[s] = &tracked{fp: fp, joined: true} // pooled, so counted as joined
		r.joined[fp]++
	}
	return prev
}

// register, get, and remove are test conveniences over the registry.
func (r *registry) register(fp string, s *yamux.Session) bool {
	r.track(fp, s)
	res, _ := r.registerConn(fp, &agentConn{fp: fp, sess: s})
	return res == registered
}

func (r *registry) get(fp string) (*yamux.Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if conns := r.byFP[fp]; len(conns) > 0 {
		return conns[0].sess, true
	}
	return nil, false
}

func (r *registry) remove(fp string, s *yamux.Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.byFP[fp] {
		if c.sess == s {
			r.removeLocked(fp, s)
			return true
		}
	}
	return false
}

// pickNext picks with a fresh rotation start, as handleIngress does for a
// request's first pick.
func (rs *routeState) pickNext(cands []*agentConn, tried map[*agentConn]bool) *agentConn {
	return rs.pick(cands, tried, rs.nextTurn())
}

func newServerSession(t *testing.T) (*yamux.Session, *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	srv, err := tunnel.ServerSession(a)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := tunnel.ClientSession(b)
	if err != nil {
		t.Fatal(err)
	}
	return srv, cli
}

func TestRegistrySetGetRemove(t *testing.T) {
	r := newRegistry()
	srv, cli := newServerSession(t)
	defer cli.Close()
	if prev := r.set("AA", srv); prev != nil {
		t.Fatal("unexpected previous session")
	}
	if _, ok := r.get("AA"); !ok {
		t.Fatal("expected AA present")
	}
	if r.remove("BB", srv) {
		t.Fatal("remove of wrong key should be a no-op")
	}
	if !r.remove("AA", srv) {
		t.Fatal("expected remove to succeed")
	}
	if _, ok := r.get("AA"); ok {
		t.Fatal("AA should be gone")
	}
}

// size and any are test-only introspection helpers for the registry: size
// counts sessions across all fingerprints.
func (r *registry) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, conns := range r.byFP {
		n += len(conns)
	}
	return n
}

func (r *registry) any() *yamux.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, conns := range r.byFP {
		if len(conns) > 0 {
			return conns[0].sess
		}
	}
	return nil
}

func TestRegistryRegisterKeepsLiveIncumbent(t *testing.T) {
	r := newRegistry()
	inc, incCli := newServerSession(t)
	defer incCli.Close()
	if !r.register("AA", inc) {
		t.Fatal("first register should succeed")
	}
	// A second live session for the same fingerprint must be refused so a
	// serving agent is never displaced by a probe or a duplicate cert.
	dup, dupCli := newServerSession(t)
	defer dupCli.Close()
	if r.register("AA", dup) {
		t.Fatal("register over a live incumbent must be refused")
	}
	if got, _ := r.get("AA"); got != inc {
		t.Fatal("the live incumbent must be retained")
	}
}

func TestRegistryRegisterReplacesDeadIncumbent(t *testing.T) {
	r := newRegistry()
	dead, deadCli := newServerSession(t)
	_ = dead.Close()
	_ = deadCli.Close()
	r.set("AA", dead) // inject a dead incumbent
	live, liveCli := newServerSession(t)
	defer liveCli.Close()
	if !r.register("AA", live) {
		t.Fatal("register over a dead incumbent should succeed")
	}
	if got, _ := r.get("AA"); got != live {
		t.Fatal("the live session should have replaced the dead incumbent")
	}
}

// Looking up live sessions leaves the pool untouched when none has closed,
// and removes the fingerprint once all have.
func TestLiveLockedWritesOnlyOnChange(t *testing.T) {
	r := newRegistry()
	r.shared["FP"] = true
	s1, c1 := newServerSession(t)
	defer c1.Close()
	s2, c2 := newServerSession(t)
	defer c2.Close()
	_, _ = r.registerConn("FP", &agentConn{fp: "FP", sess: s1})
	_, _ = r.registerConn("FP", &agentConn{fp: "FP", sess: s2})
	r.mu.Lock()
	before := r.byFP["FP"]
	live := r.liveLocked("FP")
	same := &live[0] == &before[0] && len(live) == 2
	r.mu.Unlock()
	if !same {
		t.Fatal("an unchanged pool was rewritten")
	}
	_ = s1.Close()
	r.mu.Lock()
	n := len(r.liveLocked("FP"))
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("live = %d, want 1", n)
	}
	_ = s2.Close()
	r.mu.Lock()
	_ = r.liveLocked("FP")
	_, present := r.byFP["FP"]
	r.mu.Unlock()
	if present {
		t.Fatal("an empty pool stays in the map")
	}
}
