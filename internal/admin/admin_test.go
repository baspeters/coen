package admin

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// newTestServer starts srv on a short-path Unix socket (to stay well under
// the ~104-byte AF_UNIX path limit) and waits for it to accept connections.
func newTestServer(t *testing.T, srv *Server) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, sock) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sock
}

// sendCommand dials sock, writes cmd, and returns the trimmed response line.
func sendCommand(t *testing.T, sock, cmd string) string {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(cmd)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(resp)
}

func TestHandleUnknownCommand(t *testing.T) {
	sock := newTestServer(t, &Server{})
	if resp := sendCommand(t, sock, "bogus\n"); resp != "error: unknown command" {
		t.Fatalf("got %q", resp)
	}
}

func TestHandleLevelUsage(t *testing.T) {
	sock := newTestServer(t, &Server{})
	if resp := sendCommand(t, sock, "level\n"); resp != "error: usage: level <name>" {
		t.Fatalf("got %q", resp)
	}
}

func TestHandleLevelParseError(t *testing.T) {
	sock := newTestServer(t, &Server{})
	want := `error: unknown log level "nope"`
	if resp := sendCommand(t, sock, "level nope\n"); resp != want {
		t.Fatalf("got %q, want %q", resp, want)
	}
}

func TestHandleLevelSetSuccess(t *testing.T) {
	var got slog.Level
	srv := &Server{SetLevel: func(l slog.Level) error { got = l; return nil }}
	sock := newTestServer(t, srv)
	if resp := sendCommand(t, sock, "level debug\n"); resp != "ok" {
		t.Fatalf("got %q", resp)
	}
	if got != slog.LevelDebug {
		t.Fatalf("level not applied: %v", got)
	}
}

func TestHandleLevelSetError(t *testing.T) {
	srv := &Server{SetLevel: func(slog.Level) error { return errors.New("boom") }}
	sock := newTestServer(t, srv)
	if resp := sendCommand(t, sock, "level debug\n"); resp != "error: boom" {
		t.Fatalf("got %q", resp)
	}
}

func TestSetLevelClientError(t *testing.T) {
	srv := &Server{SetLevel: func(slog.Level) error { return errors.New("denied") }}
	sock := newTestServer(t, srv)
	err := SetLevel(sock, "debug")
	if err == nil || err.Error() != "error: denied" {
		t.Fatalf("expected client error %q, got %v", "error: denied", err)
	}
}

func TestStatusDialNonexistentSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")

	if _, err := Status(sock); err == nil {
		t.Fatal("expected error dialing a nonexistent socket")
	}
}

func TestServeListenError(t *testing.T) {
	srv := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Serve(ctx, "/nonexistent-dir-for-coen-tests/a.sock"); err == nil {
		t.Fatal("expected a listen error for an unbindable socket path")
	}
}
