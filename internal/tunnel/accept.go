package tunnel

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// With ALPNv2, an agent sends one accept byte on each stream as soon as it
// takes it, before reading anything. The edge sends nothing on a new stream
// until that byte arrives; then it sends the preamble and the request head
// together. Until then the agent cannot run the request, so if the byte does
// not come (a refusal by a draining agent or one whose accept queue is full, a timeout, a dead
// session) the edge retries the request on another agent, and an agent that
// accepts late finds an empty stream. An agent must therefore not wait for
// the preamble before accepting. The price is one edge-agent round trip
// before the request goes out.
const acceptByte = 0x06

// Timing of the drain handshake, kept together so they stay consistent:
// RetireWait is how long the edge waits for stream opens in flight before it
// acknowledges a drain request, and MinAckWait, the agent's shortest wait for
// that acknowledgement, is above it with a round trip of up to RetireWait to
// spare. On a slower link the acknowledgement can come too late; the agent
// then sends GoAway anyway and only the ordering guarantee is lost.
const (
	RetireWait = 500 * time.Millisecond
	MinAckWait = 2 * RetireWait
)

// ErrBadAccept reports a stream whose first byte is not the accept byte: the
// agent does not speak the protocol it negotiated.
var ErrBadAccept = errors.New("unexpected accept byte from agent")

// ErrRefused reports a stream that ended (EOF) or was reset before the accept
// byte. With the session still open, that is the agent refusing the stream
// (when a whole session shuts down, yamux ends every stream with EOF too).
var ErrRefused = errors.New("agent refused the stream")

// Accept tells the edge the agent has taken the stream (agent side).
func Accept(w io.Writer) error {
	_, err := w.Write([]byte{acceptByte})
	return err
}

// AwaitAccept waits up to timeout for the agent's accept byte (edge side). It
// returns ErrRefused when the stream ended before the byte, and another error
// on a timeout or an unexpected byte.
func AwaitAccept(c net.Conn, timeout time.Duration) error {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, yamux.ErrConnectionReset) {
			return ErrRefused
		}
		return err
	}
	if b[0] != acceptByte {
		return ErrBadAccept
	}
	return nil
}
