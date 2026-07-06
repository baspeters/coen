package doctor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
)

func startAdmin(t *testing.T, snap obs.Snapshot) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	srv := &admin.Server{Snapshot: func() obs.Snapshot { return snap }}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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
	return sock
}

func TestAgentLiveTunnel(t *testing.T) {
	if fp, live := agentLiveTunnel(""); live || fp != "" {
		t.Fatalf("empty socket: got %q,%v", fp, live)
	}
	sock := startAdmin(t, obs.Snapshot{TunnelConnected: true, PeerFingerprint: "SHA256:edgefp"})
	if fp, live := agentLiveTunnel(sock); !live || fp != "SHA256:edgefp" {
		t.Fatalf("live tunnel: got %q,%v", fp, live)
	}
	down := startAdmin(t, obs.Snapshot{TunnelConnected: false})
	if _, live := agentLiveTunnel(down); live {
		t.Fatal("a disconnected snapshot must not report live")
	}
}

func TestCheckAgentUsesLiveTunnelWithoutProbing(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	ac, ak, _ := ca.IssueClient("agent-1")
	_ = os.WriteFile(certPath, ac, 0o600)
	_ = os.WriteFile(keyPath, ak, 0o600)

	// A closed edge port: if the active probe path ran, net:tcp reach would fail.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	_ = closed.Close()

	sock := startAdmin(t, obs.Snapshot{TunnelConnected: true, PeerFingerprint: "SHA256:edgefp"})

	cfg := &config.AgentConfig{
		Edge:  config.EdgeRef{Address: closedAddr, CA: caPath, Cert: certPath, Key: keyPath},
		Admin: config.AdminConfig{Socket: sock},
	}
	results := CheckAgent(cfg)
	if reach, _ := findResult(results, "net: tcp reach"); !reach.OK || !strings.Contains(reach.Detail, "live") {
		t.Fatalf("reachability should pass via the live tunnel, not probe the closed edge port: %+v", reach)
	}
	if mtls, _ := findResult(results, "mtls: handshake"); !mtls.OK || !strings.Contains(mtls.Detail, "live tunnel to edge SHA256:edgefp") {
		t.Fatalf("mtls should be verified via the live tunnel: %+v", mtls)
	}
}
