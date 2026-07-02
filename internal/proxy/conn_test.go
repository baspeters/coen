package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestWithPrefix(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = b.Write([]byte("DEF"))
		_ = b.Close()
	}()
	pc := WithPrefix(a, []byte("ABC"))
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ABCDEF" {
		t.Errorf("read %q, want %q", got, "ABCDEF")
	}
}

func TestIdleConnTimesOut(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ic := NewIdleConn(a, 30*time.Millisecond)
	// No writer on b: the read must fail once the idle deadline elapses.
	_, err := ic.Read(make([]byte, 4))
	if err == nil {
		t.Fatal("expected idle timeout error, got nil")
	}
}

func TestIdleConnDisabled(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ic := NewIdleConn(a, 0) // disabled: no deadline set
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = b.Write([]byte("x"))
	}()
	buf := make([]byte, 1)
	if _, err := ic.Read(buf); err != nil {
		t.Fatalf("unexpected error with idle disabled: %v", err)
	}
}
