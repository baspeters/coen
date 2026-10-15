package doctor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/obs"
)

func TestUDPBuffers(t *testing.T) {
	dir := t.TempDir()
	write := func(r, w string) {
		_ = os.WriteFile(filepath.Join(dir, "rmem_max"), []byte(r+"\n"), 0o600)
		_ = os.WriteFile(filepath.Join(dir, "wmem_max"), []byte(w+"\n"), 0o600)
	}
	write("8388608", "8388608")
	if r, ok := udpBuffers(dir); !ok || !r.OK || !strings.Contains(r.Detail, "large enough") {
		t.Fatalf("big buffers: %+v %v", r, ok)
	}
	write("4194304", "8388608")
	if r, ok := udpBuffers(dir); !ok || !r.OK || !strings.Contains(r.Detail, "net.core.rmem_max=4194304") || strings.Contains(r.Detail, "wmem") {
		t.Fatalf("small rmem: %+v %v", r, ok)
	}
	write("x", "1")
	if _, ok := udpBuffers(dir); ok {
		t.Fatal("unreadable values must be skipped")
	}
	if _, ok := udpBuffers(filepath.Join(dir, "missing")); ok {
		t.Fatal("a host without the files (not Linux) must be skipped")
	}
}

func TestCheckUDPBind(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	if r := checkUDPBind("bind: http3 (udp)", addr, ""); r.OK {
		t.Fatalf("a held UDP port passed: %+v", r)
	}
	_ = pc.Close()
	if r := checkUDPBind("bind: http3 (udp)", addr, ""); !r.OK {
		t.Fatalf("a free UDP port failed: %+v", r)
	}
}

// A held UDP port counts as coen's only when the running edge reports serving
// HTTP/3 on that port.
func TestCheckUDPBindCreditsOnlyARunningHTTP3(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")
	var serving atomic.Value
	serving.Store("")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		_ = (&admin.Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{Role: "edge", HTTP3Listen: serving.Load().(string)} }}).Serve(ctx, sock)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := admin.Status(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := checkUDPBind("bind: http3 (udp)", addr, sock); r.OK {
		t.Fatalf("an edge without HTTP/3 must not cover a held UDP port: %+v", r)
	}
	_, port, _ := net.SplitHostPort(addr)
	serving.Store("[::]:" + port) // the same port, on every address
	if r := checkUDPBind("bind: http3 (udp)", addr, sock); !r.OK || !strings.Contains(r.Detail, "HTTP/3") {
		t.Fatalf("the running edge's HTTP/3 port: %+v", r)
	}
	if r := checkUDPBind("bind: http3 (udp)", "localhost:"+port, sock); !r.OK {
		t.Fatalf("localhost names the loopback address the edge serves on: %+v", r)
	}
	serving.Store("10.255.255.1:" + port) // another address, same port
	if r := checkUDPBind("bind: http3 (udp)", addr, sock); r.OK {
		t.Fatalf("an edge on another address must not cover this one: %+v", r)
	}
}
