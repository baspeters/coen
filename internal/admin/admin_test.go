package admin

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

func TestAdminStatusAndSetLevel(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "coen.sock")
	var levelSet atomic.Value
	srv := &Server{
		Snapshot: func() obs.Snapshot { return obs.Snapshot{TunnelConnected: true, TotalStreams: 3} },
		SetLevel: func(l slog.Level) error { levelSet.Store(l); return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	snap, err := Status(sock)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !snap.TunnelConnected || snap.TotalStreams != 3 {
		t.Fatalf("bad snapshot: %+v", snap)
	}

	if err := SetLevel(sock, "debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	if levelSet.Load() != slog.LevelDebug {
		t.Fatalf("level not applied: %v", levelSet.Load())
	}
}
