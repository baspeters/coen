package doctor

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
)

func TestCheckEdgeFlagsMalformedFingerprint(t *testing.T) {
	valid := "SHA256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := &config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied", Listen: "127.0.0.1:0"},
		Tunnel:  config.TunnelServerConfig{Listen: "127.0.0.1:0"},
		Routes: []config.EdgeRoute{
			{Host: "app.example.com", AgentFingerprint: "AA"}, // malformed
			{Host: "ok.example.com", AgentFingerprint: valid},
		},
	}
	results := CheckEdge(cfg)
	if r, found := findResult(results, "config: fingerprint app.example.com"); !found || r.OK {
		t.Fatalf("malformed fingerprint should fail: found=%v %+v", found, r)
	}
	if r, found := findResult(results, "config: fingerprint ok.example.com"); !found || !r.OK {
		t.Fatalf("valid fingerprint should pass: found=%v %+v", found, r)
	}
}

func TestCheckBindReportsRunningDaemon(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")
	srv := &admin.Server{Snapshot: func() obs.Snapshot { return obs.Snapshot{} }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, sock) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, e := admin.Status(sock); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if r := checkBind("bind", addr, sock); !r.OK {
		t.Fatalf("bind should be ok when a daemon is running: %+v", r)
	} else if !strings.Contains(r.Detail, "running coen daemon") {
		t.Fatalf("expected a running-daemon note, got %q", r.Detail)
	}
	if r := checkBind("bind", addr, ""); r.OK {
		t.Fatal("bind should fail with no daemon socket")
	}
}
