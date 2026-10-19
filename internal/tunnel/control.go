package tunnel

import (
	"bufio"
	"io"
	"time"

	"github.com/baspeters/coen/internal/netx"
	"github.com/hashicorp/yamux"
)

// Streams normally flow edge -> agent. A stream the agent opens to the edge is
// a control stream carrying one line. The only message today is drainRequest:
// the agent is shutting down and asks to be taken out of the edge's pool before
// it stops accepting streams. The edge answers drainAck once it has done so.
const (
	drainRequest = "coen-drain\n"
	drainAck     = "coen-drain-ok\n"
)

// RequestDrain asks the edge on session to stop sending this agent new streams
// and waits up to timeout for the acknowledgement. It reports whether the edge
// acknowledged; an older edge does not, and the caller then relies on yamux
// GoAway alone.
//
// Frames on a session arrive in order, so once the acknowledgement is read,
// every stream the edge opened before retiring this agent has already reached
// it: the caller can accept and serve those, then stop accepting.
func RequestDrain(session *yamux.Session, timeout time.Duration) bool {
	// One deadline for the exchange. The outer bound only catches an
	// OpenStream blocked on a silently partitioned tunnel; it is a little
	// longer, so an acknowledgement read just before the deadline counts.
	deadline := time.Now().Add(timeout)
	var ok bool
	return netx.Bounded(timeout+boundGrace, func() { ok = requestDrain(session, deadline) }) && ok
}

// boundGrace is how much longer RequestDrain's outer bound runs than its
// read deadline.
const boundGrace = 100 * time.Millisecond

func requestDrain(session *yamux.Session, deadline time.Time) bool {
	s, err := session.OpenStream()
	if err != nil {
		return false
	}
	defer s.Close()
	_ = s.SetDeadline(deadline)
	if _, err := io.WriteString(s, drainRequest); err != nil {
		return false
	}
	line, err := bufio.NewReader(s).ReadString('\n')
	return err == nil && line == drainAck
}

// ServeControl accepts control streams on an edge session until it closes,
// calling onDrain when the agent asks to be drained, then acknowledging.
// Streams are handled one at a time, so an agent cannot make the edge run many
// at once. Unknown messages are ignored.
func ServeControl(session *yamux.Session, onDrain func()) {
	for {
		s, err := session.AcceptStream()
		if err != nil {
			return
		}
		serveControlStream(s, onDrain)
	}
}

func serveControlStream(s *yamux.Stream, onDrain func()) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(s, 64)).ReadString('\n')
	if err != nil || line != drainRequest {
		return
	}
	onDrain()
	_, _ = io.WriteString(s, drainAck)
}
