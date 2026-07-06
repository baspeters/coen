package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDrainWaitCompletes(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var wg sync.WaitGroup
	wg.Add(1)
	go wg.Done()
	DrainWait(log, &wg, time.Second)
	if strings.Contains(buf.String(), "drain.timeout") {
		t.Fatalf("did not expect a timeout warning: %s", buf.String())
	}
}

func TestDrainWaitTimesOut(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var wg sync.WaitGroup
	wg.Add(1) // never Done within the timeout
	DrainWait(log, &wg, 10*time.Millisecond)
	if !strings.Contains(buf.String(), "drain.timeout") {
		t.Fatalf("expected a drain.timeout warning, got: %s", buf.String())
	}
	wg.Done() // release the internal waiter goroutine
}

func TestDrainWaitZeroReturnsImmediately(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var wg sync.WaitGroup
	wg.Add(1) // not done, but a zero timeout must return at once and not warn
	DrainWait(log, &wg, 0)
	if strings.Contains(buf.String(), "drain.timeout") {
		t.Fatalf("zero timeout should not warn: %s", buf.String())
	}
	wg.Done()
}
