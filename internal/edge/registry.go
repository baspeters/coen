package edge

import (
	"sync"

	"github.com/hashicorp/yamux"
)

// registry maps an agent client-cert fingerprint to its live tunnel session.
type registry struct {
	mu       sync.RWMutex
	sessions map[string]*yamux.Session
}

func newRegistry() *registry {
	return &registry{sessions: make(map[string]*yamux.Session)}
}

// set stores s under fp and returns any session it displaced.
func (r *registry) set(fp string, s *yamux.Session) (prev *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev = r.sessions[fp]
	r.sessions[fp] = s
	return prev
}

func (r *registry) get(fp string) (*yamux.Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[fp]
	return s, ok
}

// remove deletes fp only if it still maps to s (avoids a reconnect race deleting
// the fresh session). Returns true if it deleted.
func (r *registry) remove(fp string, s *yamux.Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[fp] == s {
		delete(r.sessions, fp)
		return true
	}
	return false
}

// closeAll closes every session but leaves the map intact: each serveAgent
// goroutine removes its own entry (and updates state) when its CloseChan fires.
func (r *registry) closeAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		_ = s.Close()
	}
}
