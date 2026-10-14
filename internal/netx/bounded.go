package netx

import "time"

// Bounded runs fn on its own goroutine and waits up to d for it to return. It
// reports whether fn finished in time; if not, fn keeps running in the
// background (callers use it for calls that end once their connection closes).
func Bounded(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
