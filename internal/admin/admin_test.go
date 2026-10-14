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
	"sync"
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

// Serve removes the socket file before it returns, so a caller that waits for
// Serve never leaves a stale socket behind.
func TestServeRemovesSocketBeforeReturning(t *testing.T) {
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv := &Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{} }}
	go func() { done <- srv.Serve(ctx, sock) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve = %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after Serve returned: %v", err)
	}
}

// A daemon that exits after a newer one took over the socket path must not
// delete the newer daemon's socket.
func TestServeKeepsReplacedSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	snap := func() obs.Snapshot { return obs.Snapshot{} }

	oldCtx, stopOld := context.WithCancel(context.Background())
	oldDone := make(chan error, 1)
	go func() { oldDone <- (&Server{Snapshot: snap}).Serve(oldCtx, sock) }()
	waitStatus := func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := Status(sock); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("admin socket never answered")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitStatus()

	newCtx, stopNew := context.WithCancel(context.Background())
	newDone := make(chan struct{})
	defer func() { stopNew(); <-newDone }()                                           // no server left running past the test
	go func() { _ = (&Server{Snapshot: snap}).Serve(newCtx, sock); close(newDone) }() // replaces the path
	time.Sleep(50 * time.Millisecond)
	waitStatus()

	stopOld()
	if err := <-oldDone; err != nil {
		t.Fatalf("old Serve = %v", err)
	}
	if _, err := Status(sock); err != nil {
		t.Fatalf("the newer daemon's socket was removed by the old one: %v", err)
	}
}

// The socket-path lock is exclusive, and waiting for it is bounded.
func TestLockSocketPathIsExclusiveAndBounded(t *testing.T) {
	const wait = 150 * time.Millisecond
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	unlock, st := lockSocketPath(sock, wait)
	if st != lockHeld {
		t.Fatal("the first lock must be granted")
	}
	start := time.Now()
	u2, st2 := lockSocketPath(sock, wait)
	u2()
	if st2 != lockContended {
		t.Fatalf("a second lock while the first is held: state %v, want contended", st2)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("the wait was not bounded by lockWait (took %v)", d)
	}
	unlock()
	u3, st3 := lockSocketPath(sock, wait)
	u3()
	if st3 != lockHeld {
		t.Fatal("the lock must be granted once released")
	}
	if _, st := lockSocketPath(filepath.Join(dir, "missing-dir", "s.sock"), wait); st != lockUnavailable {
		t.Fatalf("an unusable lock location: state %v, want unavailable", st)
	}
}

// Shutdown is not held up, and the socket is left alone, when another process
// keeps the lock.
func TestServeCleanupSkipsWhenLockHeld(t *testing.T) {
	const wait = 100 * time.Millisecond
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{} }, LockWait: wait}).Serve(ctx, sock)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never answered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	unlock, st := lockSocketPath(sock, wait)
	if st != lockHeld {
		t.Fatal("could not take the lock")
	}
	defer unlock()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve blocked on the held lock during shutdown")
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("without the lock, cleanup must leave the socket in place")
	}
}

// When the lock file cannot be used at all, cleanup still removes a socket the
// daemon provably owns instead of leaving it stale.
func TestServeCleanupWithoutLockFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	// A directory where the lock file should be makes it unusable.
	if err := os.Mkdir(sock+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{} }}).Serve(ctx, sock) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never answered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket left behind without a lock file: %v", err)
	}
}

// A lock still held at startup is reported, and the daemon starts anyway.
func TestServeLogsContendedLockAtStartup(t *testing.T) {
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	unlock, st := lockSocketPath(sock, time.Second)
	if st != lockHeld {
		t.Skip("flock not available on this platform")
	}
	defer unlock()
	var buf strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) }), nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{} }, LockWait: 50 * time.Millisecond, Log: logger}).Serve(ctx, sock)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon did not start while the lock was held")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(buf.String(), "admin.socket_lock_contended") {
		t.Fatalf("missing contention warning: %s", buf.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
