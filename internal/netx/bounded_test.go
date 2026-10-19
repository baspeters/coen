package netx

import (
	"testing"
	"time"
)

func TestBounded(t *testing.T) {
	if !Bounded(time.Second, func() {}) {
		t.Fatal("a quick call must finish in time")
	}
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	if Bounded(50*time.Millisecond, func() { <-release }) {
		t.Fatal("a blocked call must time out")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Bounded waited %v", d)
	}
}
