package obs

// connectAgent lists a new agent session on s, as the edge does once it has
// accepted one.
func connectAgent(s *State, fp, addr string) *AgentSession {
	a := s.NewAgentSession(fp, addr)
	s.AddAgent(a)
	return a
}
