package edge

import (
	"net"
	"testing"

	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// newServerSession builds a real edge/agent yamux pair over net.Pipe (no TLS
// needed) and is reused by the edge routing/draining tests.
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

// size and any are test-only introspection helpers for the registry.
func (r *registry) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *registry) any() *yamux.Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		return s
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
