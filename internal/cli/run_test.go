package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/obs"
)

func TestEdgeCmdErrorsOnMissingConfig(t *testing.T) {
	if _, err := runCLI(t, "edge", "--config", "/no/such/edge.yaml"); err == nil {
		t.Fatal("expected error for missing edge config")
	}
}

func TestAgentCmdErrorsOnMissingConfig(t *testing.T) {
	if _, err := runCLI(t, "agent", "--config", "/no/such/agent.yaml"); err == nil {
		t.Fatal("expected error for missing agent config")
	}
}

func TestEdgeLevelReadsConfig(t *testing.T) {
	_, caPath, certPath, keyPath := writeTestPKI(t)
	cfgPath := filepath.Join(t.TempDir(), "edge.yaml")
	cfg := fmt.Sprintf(`
ingress:
  mode: proxied
  listen: "127.0.0.1:0"
tunnel:
  listen: "127.0.0.1:0"
  ca: %s
  cert: %s
  key: %s
routes:
  - host: "*"
    agent_fingerprint: "AA"
log:
  level: debug
  format: text
`, caPath, certPath, keyPath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	lvl, err := edgeLevel(cfgPath)
	if err != nil {
		t.Fatalf("edgeLevel: %v", err)
	}
	if lvl != "debug" {
		t.Fatalf("edgeLevel = %q, want %q", lvl, "debug")
	}
}

func TestEdgeLevelMissingConfig(t *testing.T) {
	if _, err := edgeLevel("/no/such/edge.yaml"); err == nil {
		t.Fatal("expected error for missing edge config")
	}
}

func TestAgentLevelReadsConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agent.yaml")
	cfg := `
edge:
  address: edge.example.com:2636
  ca: /a
  cert: /b
  key: /c
routes:
  - host: "*"
    service: 127.0.0.1:8080
log:
  level: warn
  format: text
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	lvl, err := agentLevel(cfgPath)
	if err != nil {
		t.Fatalf("agentLevel: %v", err)
	}
	if lvl != "warn" {
		t.Fatalf("agentLevel = %q, want %q", lvl, "warn")
	}
}

func TestAgentLevelMissingConfig(t *testing.T) {
	if _, err := agentLevel("/no/such/agent.yaml"); err == nil {
		t.Fatal("expected error for missing agent config")
	}
}

// fakeRunner is a stub runner used to drive runDaemon in tests. With ready
// and stop left nil, Run returns err immediately. When set, Run closes ready
// right after being invoked (so a test knows runDaemon has reached the point
// of launching its admin-server goroutine) and then blocks until stop is
// closed before returning err — this lets a test give the admin goroutine as
// much time as it needs without racing runDaemon's shutdown (which happens
// as soon as Run returns).
type fakeRunner struct {
	err   error
	ready chan struct{}
	stop  chan struct{}
}

func (f fakeRunner) Run(_ context.Context) error {
	if f.ready != nil {
		close(f.ready)
	}
	if f.stop != nil {
		<-f.stop
	}
	return f.err
}

func TestRunDaemonNoSocket(t *testing.T) {
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	state := &obs.State{}
	reload := func() (string, error) { return "info", nil }
	wantErr := errors.New("boom")

	if err := runDaemon(log, lv, state, "", reload, fakeRunner{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("runDaemon = %v, want %v", err, wantErr)
	}
}

func TestRunDaemonWithSocket(t *testing.T) {
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	state := &obs.State{}
	reload := func() (string, error) { return "info", nil }
	wantErr := errors.New("boom")

	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")

	ready := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runDaemon(log, lv, state, sock, reload, fakeRunner{err: wantErr, ready: ready, stop: stop})
	}()

	<-ready // runDaemon has launched the admin server goroutine

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, statusErr := admin.Status(sock); statusErr == nil {
			break
		}
		if time.Now().After(deadline) {
			close(stop)
			t.Fatal("admin server never came up on socket")
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(stop)
	if err := <-done; !errors.Is(err, wantErr) {
		t.Fatalf("runDaemon = %v, want %v", err, wantErr)
	}
}

// TestEdgeCmdBindFailure drives newEdgeCmd's full body — config load, logger
// setup, edge.New, then runDaemon calling into edge.Run — by pointing
// tunnel.listen at a port that's already bound, so edge.Run's listener setup
// fails fast and the command surfaces that error.
func TestEdgeCmdBindFailure(t *testing.T) {
	_, caPath, certPath, keyPath := writeTestPKI(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	cfgPath := filepath.Join(t.TempDir(), "edge.yaml")
	cfg := fmt.Sprintf(`
ingress:
  mode: proxied
  listen: "127.0.0.1:0"
tunnel:
  listen: %q
  ca: %s
  cert: %s
  key: %s
routes:
  - host: "*"
    agent_fingerprint: "AA"
log:
  level: info
  format: text
`, ln.Addr().String(), caPath, certPath, keyPath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, err := runCLI(t, "edge", "--config", cfgPath)
	if err == nil {
		t.Fatalf("expected a bind failure, got output: %s", out)
	}
	if !strings.Contains(err.Error(), "tunnel listen") {
		t.Fatalf("expected a tunnel listen error, got %v", err)
	}
}
