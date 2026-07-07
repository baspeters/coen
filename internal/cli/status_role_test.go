package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

func TestRenderStatusEdgeOmitsAgentFields(t *testing.T) {
	var buf bytes.Buffer
	renderStatus(&buf, obs.Snapshot{
		Role:              "edge",
		Agents:            []obs.AgentInfo{{Fingerprint: "SHA256:xyz", RemoteAddr: "198.51.100.7:4444", ConnectedSince: time.Unix(0, 0)}},
		HandshakeOK:       2,
		HandshakeRejected: 22,
	}, false)
	s := buf.String()
	if !strings.Contains(s, "role:       edge") {
		t.Fatalf("missing role line: %s", s)
	}
	// Agent line format is "  - <IP> (<SINCE>, <SHA256>)": connecting IP (no
	// ephemeral port), then connect time and fingerprint in parentheses.
	if !strings.Contains(s, "  - 198.51.100.7 (") || !strings.Contains(s, ", SHA256:xyz)") {
		t.Fatalf("edge status should show '  - <IP> (<SINCE>, <SHA256>)': %s", s)
	}
	if strings.Contains(s, "198.51.100.7:4444") {
		t.Fatalf("agent line should drop the ephemeral source port: %s", s)
	}
	if !strings.Contains(s, "handshakes: 2 ok / 0 fail / 22 rejected") {
		t.Fatalf("edge status should split handshakes into ok/fail/rejected: %s", s)
	}
	if strings.Contains(s, "tunnel:") {
		t.Fatalf("edge status must not show the agent-only tunnel field: %s", s)
	}
}

func TestRenderStatusAgentOmitsEdgeFields(t *testing.T) {
	var buf bytes.Buffer
	renderStatus(&buf, obs.Snapshot{
		Role: "agent", TunnelConnected: true, PeerFingerprint: "SHA256:edge", ConnectedSince: time.Unix(0, 0),
	}, false)
	s := buf.String()
	if !strings.Contains(s, "tunnel:     connected") || !strings.Contains(s, "peer_fp:") {
		t.Fatalf("agent status missing tunnel/peer: %s", s)
	}
	if strings.Contains(s, "agents:") {
		t.Fatalf("agent status must not show the edge-only agents field: %s", s)
	}
}

const edgeCfgBody = `
ingress:
  mode: proxied
  listen: "127.0.0.1:8000"
tunnel:
  listen: ":2636"
  ca: /a
  cert: /b
  key: /c
routes:
  - host: app.example.com
    agent_fingerprint: "AA"
`

func TestAdminSocketFromConfig(t *testing.T) {
	dir := t.TempDir()
	withSock := filepath.Join(dir, "edge.yaml")
	if err := os.WriteFile(withSock, []byte(edgeCfgBody+"admin:\n  socket: /run/coen/edge.sock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := adminSocketFromConfig("edge", withSock); err != nil || got != "/run/coen/edge.sock" {
		t.Fatalf("adminSocketFromConfig = %q, %v; want /run/coen/edge.sock", got, err)
	}

	noSock := filepath.Join(dir, "edge2.yaml")
	if err := os.WriteFile(noSock, []byte(edgeCfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminSocketFromConfig("edge", noSock); err == nil {
		t.Fatal("expected an error when admin.socket is missing")
	}
}

func TestResolveStatusSocketNoDaemon(t *testing.T) {
	old := enumerate
	t.Cleanup(func() { enumerate = old })
	enumerate = func() ([]daemon, error) { return nil, nil }
	if _, err := resolveStatusSocket("", ""); err == nil || !strings.Contains(err.Error(), "no running coen daemon") {
		t.Fatalf("want a no-daemon error, got %v", err)
	}
}
