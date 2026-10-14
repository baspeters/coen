package tunnel

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestAcceptRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = Accept(a) }()
	if err := AwaitAccept(b, time.Second); err != nil {
		t.Fatalf("AwaitAccept = %v", err)
	}
}

func TestAwaitAcceptRefusedOnClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	_ = a.Close()
	if err := AwaitAccept(b, time.Second); !errors.Is(err, ErrRefused) {
		t.Fatalf("closed before accepting: %v, want ErrRefused", err)
	}
}

func TestAwaitAcceptTimeoutAndBadByteAreNotRefusals(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := AwaitAccept(b, 50*time.Millisecond); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("timeout: %v; must be an error other than ErrRefused", err)
	}
	go func() { _, _ = a.Write([]byte{'x'}) }()
	if err := AwaitAccept(b, time.Second); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("bad byte: %v; must be an error other than ErrRefused", err)
	}
	if MinAckWait <= RetireWait {
		t.Fatal("the agent's acknowledgement wait must exceed the edge's retire wait")
	}
}
