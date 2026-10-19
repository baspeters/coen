package edge

import "context"

// semaphore is a non-blocking counting limiter. A nil *semaphore is unlimited.
type semaphore struct {
	ch chan struct{}
}

func newSemaphore(n int) *semaphore {
	if n <= 0 {
		return nil // unlimited
	}
	return &semaphore{ch: make(chan struct{}, n)}
}

func (s *semaphore) tryAcquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// acquire waits for a slot until ctx ends, and reports whether it got one.
func (s *semaphore) acquire(ctx context.Context) bool {
	if s == nil {
		return true
	}
	select {
	case s.ch <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *semaphore) release() {
	if s == nil {
		return
	}
	<-s.ch
}
