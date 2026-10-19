package edge

import (
	"crypto/tls"
	"net"
)

// wireConn counts the bytes read from the network, beneath any TLS layer, so
// the edge can tell a connection that sent nothing (a TCP health check or port
// scan) from a TLS client that sent a ClientHello and then dropped the
// handshake without an alert (for example after rejecting the certificate).
type wireConn struct {
	net.Conn
	// sawBytes is set by any read that returns data. tls.Conn serializes
	// reads, and handleIngress checks it on the goroutine that performed them
	// (before the proxy goroutines start), so a plain bool suffices.
	sawBytes bool
	// tunnel is set during the TLS handshake when the client offered the
	// tunnel's ALPN protocol on an ingress shared with the tunnel (see
	// ingressTLSConfig); it is read after the handshake, on the same
	// goroutine.
	tunnel bool
}

func (c *wireConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.sawBytes = true
	}
	return n, err
}

// wireListener wraps every accepted connection in a wireConn.
type wireListener struct{ net.Listener }

func (l wireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &wireConn{Conn: c}, nil
}

// closedWithoutRequest reports whether an ingress connection that ended before
// any request byte (errNoRequest) was benign: a plain TCP connection that sent
// nothing, a TLS connection that sent nothing on the wire, or a TLS connection
// that completed its handshake and then closed or idled unused (a browser
// preconnect). A TLS handshake abandoned or stalled after the ClientHello is
// not benign.
// Any other connection type cannot be classified, so it is conservatively not
// treated as benign and stays a counted bad request.
func closedWithoutRequest(conn net.Conn) bool {
	switch c := conn.(type) {
	case *tls.Conn:
		if c.ConnectionState().HandshakeComplete {
			return true
		}
		wc, ok := c.NetConn().(*wireConn)
		return ok && !wc.sawBytes
	case *net.TCPConn:
		return true
	default:
		return false
	}
}
