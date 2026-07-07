package edge

import (
	"net"
	"testing"
	"time"
)

// A bare TCP connect that closes before the TLS handshake (health check, LB
// probe, port scan, or `coen doctor`'s reachability probe) must not be counted
// as a handshake failure.
func TestServeAgentIncompleteHandshakeNotCountedFail(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	defer tunLn.Close()
	defer ingressLn.Close()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := tunLn.Accept()
		if err != nil {
			return
		}
		e.serveAgent(conn)
	}()

	c, err := net.Dial("tcp", tunLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close() // gone before sending a ClientHello

	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serveAgent did not return after an incomplete handshake")
	}

	snap := e.state.Snapshot()
	if snap.HandshakeFail != 0 || snap.HandshakeRejected != 0 {
		t.Fatalf("incomplete handshake must not count as fail/rejected, got fail=%d rejected=%d", snap.HandshakeFail, snap.HandshakeRejected)
	}
	if e.reg.size() != 0 {
		t.Fatal("no session should be registered")
	}
}
