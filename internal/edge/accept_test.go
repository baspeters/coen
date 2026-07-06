package edge

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mutexBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *mutexBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *mutexBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// transientListener returns a transient error on the first three Accepts, then
// blocks until ctx is cancelled and reports the listener closed.
type transientListener struct {
	mu    sync.Mutex
	calls int
	done  <-chan struct{}
}

func (l *transientListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	n := l.calls
	l.mu.Unlock()
	if n <= 3 {
		return nil, errors.New("temporary accept failure")
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *transientListener) count() int   { l.mu.Lock(); defer l.mu.Unlock(); return l.calls }
func (l *transientListener) Close() error { return nil }
func (l *transientListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "t", Net: "unix"}
}

func TestAcceptLoopRetriesTransientErrors(t *testing.T) {
	old := acceptRetryDelay
	acceptRetryDelay = time.Millisecond
	t.Cleanup(func() { acceptRetryDelay = old })

	var buf mutexBuf
	e := &Edge{log: slog.New(slog.NewTextHandler(&buf, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	ln := &transientListener{done: ctx.Done()}

	done := make(chan struct{})
	go func() { e.acceptTunnel(ctx, ln); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for ln.count() < 4 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("accept loop did not retry transient errors (calls=%d)", ln.count())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept loop did not return after ctx cancel")
	}
	if !strings.Contains(buf.String(), "accept.error") {
		t.Fatalf("expected an accept.error log line, got: %s", buf.String())
	}
}
