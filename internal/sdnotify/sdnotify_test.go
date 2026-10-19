package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// listen makes a notification socket at path (or the abstract name) and
// returns a function that reads one message from it.
func listen(t *testing.T, name string) func() string {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return func() string {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}
}

func TestNotify(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if Available() {
		t.Fatal("no socket: not available")
	}
	if sent, err := Notify("READY=1"); sent || err != nil {
		t.Fatalf("no socket: %v %v", sent, err)
	}

	// A short path: macOS limits unix socket paths to about 100 bytes.
	dir, err := os.MkdirTemp("/tmp", "sdn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "n.sock")
	read := listen(t, path)
	t.Setenv("NOTIFY_SOCKET", path)
	if !Available() {
		t.Fatal("socket set: available")
	}
	if sent, err := Notify("READY=1\nSTATUS=serving"); !sent || err != nil {
		t.Fatalf("%v %v", sent, err)
	}
	if got := read(); got != "READY=1\nSTATUS=serving" {
		t.Fatalf("got %q", got)
	}

	t.Setenv("NOTIFY_SOCKET", filepath.Join(dir, "missing.sock"))
	if sent, err := Notify("READY=1"); !sent || err == nil {
		t.Fatalf("a socket that is not there: %v %v", sent, err)
	}
}

func TestNotifyAbstractSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract unix sockets are Linux only")
	}
	name := "@coen-sdnotify-test"
	read := listen(t, "\x00"+name[1:])
	t.Setenv("NOTIFY_SOCKET", name)
	if sent, err := Notify("MAINPID=42"); !sent || err != nil {
		t.Fatalf("%v %v", sent, err)
	}
	if got := read(); got != "MAINPID=42" {
		t.Fatalf("got %q", got)
	}
}
