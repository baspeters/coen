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
