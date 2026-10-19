package tunnel

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDrainHandshake(t *testing.T) {
	a, b := net.Pipe()
	edge, err := ServerSession(a)
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	agent, err := ClientSession(b)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	var drained atomic.Int32
	go ServeControl(edge, func() { drained.Add(1) })
	if !RequestDrain(agent, 2*time.Second) {
		t.Fatal("the edge did not acknowledge the drain request")
	}
	if drained.Load() != 1 {
		t.Fatalf("onDrain calls = %d, want 1", drained.Load())
	}
}

// An edge that does not serve control streams (an older version) never
// acknowledges; the agent gives up after the timeout.
func TestDrainWithoutControlServer(t *testing.T) {
	a, b := net.Pipe()
	edge, _ := ServerSession(a)
	defer edge.Close()
	agent, _ := ClientSession(b)
	defer agent.Close()
	start := time.Now()
	if RequestDrain(agent, 200*time.Millisecond) {
		t.Fatal("no edge acknowledged, yet RequestDrain reported success")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("RequestDrain did not respect its timeout (%v)", d)
	}
	_ = agent.Close()
	if RequestDrain(agent, time.Second) {
		t.Fatal("a closed session cannot be drained")
	}
}

// Anything but a drain request on a control stream is ignored.
func TestServeControlIgnoresUnknownMessages(t *testing.T) {
	a, b := net.Pipe()
	edge, _ := ServerSession(a)
	defer edge.Close()
	agent, _ := ClientSession(b)
	defer agent.Close()
	var drained atomic.Int32
	go ServeControl(edge, func() { drained.Add(1) })
	s, err := agent.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte("hello\n"))
	_ = s.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, _ := s.Read(buf)
	if n != 0 || drained.Load() != 0 {
		t.Fatalf("unknown message answered (%q) or drained (%d)", buf[:n], drained.Load())
	}
}
