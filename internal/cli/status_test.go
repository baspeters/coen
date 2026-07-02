package cli

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/obs"
)

func TestStatusCommand(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	srv := &admin.Server{
		Snapshot: func() obs.Snapshot { return obs.Snapshot{TunnelConnected: true, TotalStreams: 5} },
		SetLevel: func(slog.Level) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := admin.Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	out, err := runCLI(t, "status", "--socket", sock, "--json")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "\"total_streams\": 5") {
		t.Fatalf("unexpected output: %s", out)
	}
}
