package proxy

import (
	"bytes"
	"io"
	"net"
	"time"
)

// IdleConn resets a rolling deadline on every Read and Write when idle > 0, so a
// connection with no traffic for `idle` is closed by its own deadline. idle <= 0
// disables the behavior (no deadline is ever set).
type IdleConn struct {
	net.Conn
	idle time.Duration
}

// NewIdleConn wraps c with a rolling idle deadline.
func NewIdleConn(c net.Conn, idle time.Duration) *IdleConn {
	return &IdleConn{Conn: c, idle: idle}
}

func (c *IdleConn) bump() {
	if c.idle > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
}

func (c *IdleConn) Read(b []byte) (int, error)  { c.bump(); return c.Conn.Read(b) }
func (c *IdleConn) Write(b []byte) (int, error) { c.bump(); return c.Conn.Write(b) }

// PrefixConn prepends already-read bytes to the read side of a conn. Writes and
// Close pass straight through to the underlying conn.
type PrefixConn struct {
	net.Conn
	r io.Reader
}

// WithPrefix returns a conn that yields prefix first, then the conn's own bytes.
func WithPrefix(c net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func (p *PrefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }
