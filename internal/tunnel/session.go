package tunnel

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// ServerSession wraps the edge side of the tunnel (accepts the TCP/TLS conn).
func ServerSession(conn net.Conn) (*yamux.Session, error) {
	return yamux.Server(conn, yamuxConfig())
}

// ClientSession wraps the agent side of the tunnel (dialed the TCP/TLS conn).
func ClientSession(conn net.Conn) (*yamux.Session, error) {
	return yamux.Client(conn, yamuxConfig())
}

// IsTeardown reports whether err means the peer, stream, or session went away
// (closed, reset, or shut down, for example during an edge restart) rather than
// that the peer sent something malformed, truncated (io.ErrUnexpectedEOF), or
// nothing at all in time.
func IsTeardown(err error) bool {
	for _, target := range []error{io.EOF, net.ErrClosed, yamux.ErrStreamClosed, yamux.ErrSessionShutdown, yamux.ErrConnectionReset} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
