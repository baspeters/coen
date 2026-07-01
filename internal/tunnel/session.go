package tunnel

import (
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
