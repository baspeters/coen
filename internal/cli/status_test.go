package cli

import (
	"context"
	"log/slog"
	"os"
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

// TestStatusCommandHuman exercises newStatusCmd's human-readable (non-JSON)
// output path against a real admin.Server stub.
func TestStatusCommandHuman(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")

	srv := &admin.Server{
		Snapshot: func() obs.Snapshot {
			return obs.Snapshot{TunnelConnected: true, TotalStreams: 3, ActiveStreams: 1}
		},
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

	// --json is passed explicitly (even though false is the flag's default)
	// because newStatusCmd's flag variable is shared across every runCLI
	// call in this process (subcommands are built once via init/register),
	// so TestStatusCommand's --json=true would otherwise leak here.
	out, err := runCLI(t, "status", "--socket", sock, "--json=false")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "tunnel:") {
		t.Fatalf("expected output to contain %q, got %q", "tunnel:", out)
	}
	if !strings.Contains(out, "streams:") {
		t.Fatalf("expected output to contain %q, got %q", "streams:", out)
	}
}
