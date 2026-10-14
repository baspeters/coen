package netx

import (
	"errors"
	"net"
	"testing"
)

func TestIsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = net.Listen("tcp", ln.Addr().String())
	if !IsAddrInUse(err) {
		t.Fatalf("a real busy-port error must be recognised: %v", err)
	}
	if IsAddrInUse(errors.New("other")) || IsAddrInUse(nil) {
		t.Fatal("unrelated errors are not address-in-use")
	}
}

func TestIsAddrNotAvail(t *testing.T) {
	_, err := net.Listen("tcp", "192.0.2.123:0") // TEST-NET-1, never assigned
	if !IsAddrNotAvail(err) {
		t.Fatalf("an unassigned address must be recognised: %v", err)
	}
	if IsAddrNotAvail(errors.New("other")) {
		t.Fatal("unrelated errors are not address-not-available")
	}
}
