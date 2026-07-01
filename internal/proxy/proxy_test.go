package proxy

import (
	"io"
	"net"
	"testing"
)

func TestPipeBidirectional(t *testing.T) {
	c1, s1 := net.Pipe() // client external end c1, internal end s1
	s2, c2 := net.Pipe() // internal end s2, backend external end c2
	done := make(chan struct{})
	var aToB, bToA int64
	var perr error
	go func() { aToB, bToA, perr = Pipe(s1, s2); close(done) }()

	go func() { _, _ = c1.Write([]byte("hello")) }()
	got := make([]byte, 5)
	if _, err := io.ReadFull(c2, got); err != nil {
		t.Fatalf("read backend: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("backend got %q", got)
	}

	go func() { _, _ = c2.Write([]byte("world")) }()
	back := make([]byte, 5)
	if _, err := io.ReadFull(c1, back); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if string(back) != "world" {
		t.Fatalf("client got %q", back)
	}

	_ = c1.Close()
	_ = c2.Close()
	<-done
	if perr != nil {
		t.Fatalf("Pipe returned unexpected error on normal close: %v", perr)
	}
	if aToB != 5 || bToA != 5 {
		t.Fatalf("byte counts aToB=%d bToA=%d, want 5/5", aToB, bToA)
	}
}
