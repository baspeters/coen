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

func TestAdminSocketFromConfigUnknownRole(t *testing.T) {
	if _, err := adminSocketFromConfig("bogus", "x"); err == nil {
		t.Fatal("expected an error for an unknown role")
	}
}

func TestResolveStatusSocketExplicitRole(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "edge.yaml")
	if err := os.WriteFile(cfg, []byte(edgeCfgBody+"admin:\n  socket: /run/coen/edge.sock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveStatusSocket("edge", cfg)
	if err != nil || got != "/run/coen/edge.sock" {
		t.Fatalf("resolveStatusSocket(edge) = %q, %v", got, err)
	}
}

// TestStatusCommandAutoDetect drives `coen status` with no flags: it detects the
// role from a (faked) running daemon, reads the socket from that daemon's
// config, connects, and renders role-aware output.
func TestStatusCommandAutoDetect(t *testing.T) {
	sdir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sdir) })
	sock := filepath.Join(sdir, "a.sock")
	srv := &admin.Server{
		Snapshot: func() obs.Snapshot { return obs.Snapshot{Role: "agent", TunnelConnected: true} },
		SetLevel: func(slog.Level) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, sock) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, e := admin.Status(sock); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cfg := filepath.Join(t.TempDir(), "agent.yaml")
	body := "edge:\n  address: 127.0.0.1:2636\n  ca: /a\n  cert: /b\n  key: /c\n" +
		"routes:\n  - host: app.example.com\n    service: 127.0.0.1:8080\n" +
		"admin:\n  socket: " + sock + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	old := enumerate
	t.Cleanup(func() { enumerate = old })
	enumerate = func() ([]daemon, error) { return []daemon{{role: "agent", config: cfg}}, nil }

	out, err := runCLI(t, "status", "--json=false")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "role:       agent") || !strings.Contains(out, "tunnel:     connected") {
		t.Fatalf("expected auto-detected agent status, got: %s", out)
	}
}
