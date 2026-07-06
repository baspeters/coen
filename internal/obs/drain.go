package obs

import (
	"log/slog"
	"sync"
	"time"
)

// DrainWait waits for wg to complete, up to timeout. A non-positive timeout
// returns immediately without waiting. If the timeout elapses first, it logs a
// "drain.timeout" warning via log. It is shared by the edge and agent shutdown
// paths, which drain in-flight work the same way.
func DrainWait(log *slog.Logger, wg *sync.WaitGroup, timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Warn("drain.timeout", "after", timeout.String())
	}
}
