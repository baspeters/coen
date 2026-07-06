package tunnel

import (
	"crypto/tls"
	"testing"
)

// A nil CA pool must not leave RootCAs/ClientCAs nil (which would fall back to
// the system trust store / accept-nothing ambiguity); it must fail closed.
func TestTLSConfigNilPoolFailsClosed(t *testing.T) {
	if c := ClientTLSConfig(nil, tls.Certificate{}, "edge.example.com"); c.RootCAs == nil {
		t.Fatal("ClientTLSConfig(nil) left RootCAs nil (would trust system roots)")
	}
	if c := ServerTLSConfig(nil, tls.Certificate{}); c.ClientCAs == nil {
		t.Fatal("ServerTLSConfig(nil) left ClientCAs nil")
	}
}
