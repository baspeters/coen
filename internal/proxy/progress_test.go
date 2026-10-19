package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Progress reports every byte in each direction, and the reported sums equal
// the returned totals.
func TestPipeProgressReportsAllBytes(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	var toB, toA atomic.Int64
	done := make(chan struct{})
	var gotA, gotB int64
	go func() {
		gotA, gotB, _ = PipeProgress(a2, b1, func(n int64) { toB.Add(n) }, func(n int64) { toA.Add(n) })
		close(done)
	}()
	payloadAB := bytes.Repeat([]byte("x"), 100000)
	payloadBA := bytes.Repeat([]byte("y"), 7000)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = a1.Write(payloadAB) }()
	go func() { defer wg.Done(); _, _ = io.ReadFull(b2, make([]byte, len(payloadAB))) }()
	wg.Wait()
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = b2.Write(payloadBA) }()
	go func() { defer wg.Done(); _, _ = io.ReadFull(a1, make([]byte, len(payloadBA))) }()
	wg.Wait()
	// Live: progress reflects the traffic before the pipe ends. The reader
	// can see the bytes just before the writer reports them, so poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for toB.Load() != int64(len(payloadAB)) || toA.Load() != int64(len(payloadBA)) {
		if time.Now().After(deadline) {
			t.Fatalf("live progress = %d/%d, want %d/%d", toB.Load(), toA.Load(), len(payloadAB), len(payloadBA))
		}
		time.Sleep(time.Millisecond)
	}
	_ = a1.Close()
	<-done
	if gotA != toB.Load() || gotB != toA.Load() {
		t.Fatalf("totals %d/%d disagree with progress %d/%d", gotA, gotB, toB.Load(), toA.Load())
	}
}
