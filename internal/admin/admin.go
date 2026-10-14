package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

// Server answers status/control requests on a local Unix socket.
type Server struct {
	Snapshot func() obs.Snapshot
	SetLevel func(slog.Level) error
	// Timeout bounds a single server-side request; zero uses defaultHandleTimeout.
	Timeout time.Duration
	// LockWait bounds how long the socket-path lock is waited for; zero uses
	// defaultLockWait.
	LockWait time.Duration
	// Log, when set, receives warnings (for example a contended socket lock).
	Log *slog.Logger
}

// defaultHandleTimeout bounds how long a single admin request (server side) or
// client call may take, so a stalled or hostile local client cannot pin a
// goroutine or fd on the daemon, and a wedged daemon cannot hang the CLI.
const defaultHandleTimeout = 5 * time.Second

// maxRequestBytes caps an admin request line so a client cannot force unbounded
// buffering by never sending a newline.
const maxRequestBytes = 4 << 10

// defaultLockWait bounds the socket-path lock wait (see lockSocketPath).
const defaultLockWait = 2 * time.Second

func (s *Server) lockWait() time.Duration {
	if s.LockWait > 0 {
		return s.LockWait
	}
	return defaultLockWait
}

func (s *Server) reqTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return defaultHandleTimeout
}

func (s *Server) Serve(ctx context.Context, socketPath string) error {
	unlock, state := lockSocketPath(socketPath, s.lockWait())
	if state == lockContended && s.Log != nil {
		// Another process held the lock past the wait (a stuck daemon busy
		// with this path). Starting matters more; say so, since that process
		// could still remove the socket we are about to create.
		s.Log.Warn("admin.socket_lock_contended", "socket", socketPath, "wait", s.lockWait().String())
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		unlock()
		return fmt.Errorf("admin listen: %w", err)
	}
	// Record which file is ours right after creating it: a newer daemon may
	// replace the path while this one is still draining, and its socket must
	// survive our exit. The listener would unlink the path on Close
	// regardless, so turn that off; cleanup removes it only while it is ours.
	// If the path cannot be stat'ed, ownership cannot be proven later, so the
	// socket is left in place on exit rather than risk removing a newer
	// daemon's.
	ours, _ := os.Stat(socketPath)
	unlock()
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	cleanup := func() {
		_ = ln.Close()
		// Under the same lock a newer daemon holds while it replaces the
		// path, so the check and the remove cannot straddle its Listen. If
		// another process holds the lock, it is working on the path: leave
		// the socket rather than guess. Without locking at all, proceed with
		// the ownership check alone.
		unlock, state := lockSocketPath(socketPath, s.lockWait())
		defer unlock()
		if state == lockContended {
			return
		}
		if cur, err := os.Stat(socketPath); err == nil && ours != nil && os.SameFile(ours, cur) {
			_ = os.Remove(socketPath)
		}
	}
	// Restrict the control socket to its owner; do not rely on umask or the
	// systemd unit's directory mode as the security boundary.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("admin chmod: %w", err)
	}
	// Every return path runs cleanup, which removes the socket while it is
	// provably ours (identified at creation and still in place, checked under
	// the lock). Otherwise it is left, and a later daemon replaces it on start.
	defer cleanup()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-stop:
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.reqTimeout()))
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestBytes)).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "status":
		b, _ := json.Marshal(s.Snapshot())
		_, _ = conn.Write(append(b, '\n'))
	case "level":
		if len(fields) != 2 {
			fmt.Fprintln(conn, "error: usage: level <name>")
			return
		}
		lvl, err := obs.ParseLevel(fields[1])
		if err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		if err := s.SetLevel(lvl); err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		fmt.Fprintln(conn, "ok")
	default:
		fmt.Fprintln(conn, "error: unknown command")
	}
}

// Status connects to the admin socket and returns the daemon snapshot.
func Status(socketPath string) (obs.Snapshot, error) {
	conn, err := net.DialTimeout("unix", socketPath, defaultHandleTimeout)
	if err != nil {
		return obs.Snapshot{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(defaultHandleTimeout))
	if _, err := conn.Write([]byte("status\n")); err != nil {
		return obs.Snapshot{}, err
	}
	var snap obs.Snapshot
	if err := json.NewDecoder(conn).Decode(&snap); err != nil {
		return obs.Snapshot{}, err
	}
	return snap, nil
}

// SetLevel connects to the admin socket and changes the runtime log level.
func SetLevel(socketPath, level string) error {
	conn, err := net.DialTimeout("unix", socketPath, defaultHandleTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(defaultHandleTimeout))
	fmt.Fprintf(conn, "level %s\n", level)
	resp, _ := bufio.NewReader(conn).ReadString('\n')
	if resp = strings.TrimSpace(resp); resp != "ok" {
		return fmt.Errorf("%s", resp)
	}
	return nil
}
