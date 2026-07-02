package edge

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

func (s *semaphore) release() {
	if s == nil {
		return
	}
	<-s.ch
}
