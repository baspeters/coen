package cli

import (
	"bytes"
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

func TestStatusCommandShowsAgents(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	srv := &admin.Server{
		Snapshot: func() obs.Snapshot {
			return obs.Snapshot{Agents: []obs.AgentInfo{{Fingerprint: "SHA256:abc", ConnectedSince: time.Now()}}}
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

	out, err := runCLI(t, "status", "--socket", sock, "--json=false")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "agents:") || !strings.Contains(out, "SHA256:abc") {
		t.Fatalf("expected an agents block with the fingerprint, got %q", out)
	}
}

func TestRenderEdgeStatusShowsDraining(t *testing.T) {
	var buf strings.Builder
	renderStatus(&buf, obs.Snapshot{Role: "edge", Agents: []obs.AgentInfo{
		{Fingerprint: "SHA256:a", RemoteAddr: "10.0.0.1:5"},
		{Fingerprint: "SHA256:b", RemoteAddr: "10.0.0.2:5", Draining: true},
	}}, false)
	out := buf.String()
	if !strings.Contains(out, "2 sessions (1 draining), 2 certificates") || !strings.Contains(out, "SHA256:b, draining)") || strings.Contains(out, "SHA256:a, draining") {
		t.Fatalf("draining not rendered:\n%s", out)
	}
}

func TestRenderEdgeStatusCountsSessionsAndCertificates(t *testing.T) {
	var buf strings.Builder
	renderStatus(&buf, obs.Snapshot{Role: "edge", Agents: []obs.AgentInfo{
		{Fingerprint: "SHA256:s", RemoteAddr: "10.0.0.1:5"},
		{Fingerprint: "SHA256:s", RemoteAddr: "10.0.0.2:5"},
	}}, false)
	if !strings.Contains(buf.String(), "2 sessions, 1 certificate") {
		t.Fatalf("two sessions on one certificate not rendered as such:\n%s", buf.String())
	}
}

// Refusals of duplicate and over-cap sessions show only once there are any.
func TestRenderEdgeStatusShowsRefusedSessions(t *testing.T) {
	var plain bytes.Buffer
	renderEdgeStatus(&plain, obs.Snapshot{Role: "edge", HandshakeOK: 1})
	if strings.Contains(plain.String(), "capped") {
		t.Fatalf("no refusals, yet they are shown:\n%s", plain.String())
	}
	var b bytes.Buffer
	renderEdgeStatus(&b, obs.Snapshot{Role: "edge", HandshakeOK: 1, HandshakeDup: 2, HandshakeCapped: 3})
	if !strings.Contains(b.String(), "1 ok / 0 fail / 0 rejected / 2 duplicate / 3 capped") {
		t.Fatalf("refusals not shown:\n%s", b.String())
	}
}

// One session reads in the singular.
func TestRenderEdgeStatusSingularSession(t *testing.T) {
	var buf strings.Builder
	renderStatus(&buf, obs.Snapshot{Role: "edge", Agents: []obs.AgentInfo{{Fingerprint: "SHA256:a", Draining: true}}}, false)
	if !strings.Contains(buf.String(), "1 session (1 draining), 1 certificate") {
		t.Fatalf("not singular:\n%s", buf.String())
	}
}
