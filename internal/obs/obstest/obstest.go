// Package obstest has helpers for tests that need obs state.
package obstest

import "github.com/baspeters/coen/internal/obs"

// ConnectAgent lists a new agent session on s, as the edge does once it has
// accepted one.
func ConnectAgent(s *obs.State, fp, addr string) *obs.AgentSession {
	a := s.NewAgentSession(fp, addr)
	s.AddAgent(a)
	return a
}
