package admin

import (
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestAdminSocketIsOwnerOnly(t *testing.T) {
	sock := newTestServer(t, &Server{})
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 600", perm)
	}
}

func TestHandleTimesOutOnStalledClient(t *testing.T) {
	sock := newTestServer(t, &Server{Timeout: 50 * time.Millisecond})
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Send no newline: the server must close the connection when handleTimeout
	// fires rather than blocking on ReadString forever.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected server to close the stalled connection (EOF), got %v", err)
	}
}
