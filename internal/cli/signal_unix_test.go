//go:build unix

package cli

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

// signalRunner blocks until ctx ends, then reports whether the state was
// already marked draining at that moment.
type signalRunner struct {
	ready    chan struct{}
	st       *obs.State
	draining chan bool
}

func (r signalRunner) Run(ctx context.Context) error {
	close(r.ready)
	<-ctx.Done()
	r.draining <- r.st.Detail().Draining
	return nil
}

// SIGTERM marks the state draining before the daemon's context is cancelled,
// so a replacement probing the metrics port never sees a closing daemon that
// still reports coen_draining 0.
func TestRunDaemonMarksDrainingBeforeCancel(t *testing.T) {
	log, lv, _ := obs.NewLogger("info", "text", io.Discard)
	st := obs.NewState("edge")
	r := signalRunner{ready: make(chan struct{}), st: st, draining: make(chan bool, 1)}
	done := make(chan error, 1)
	go func() { done <- runDaemon(log, lv, st, daemonOpts{}, func() (string, error) { return "info", nil }, r) }()
	<-r.ready
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-r.draining:
		if !d {
			t.Fatal("ctx was cancelled before the state was marked draining")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM did not stop the daemon")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
