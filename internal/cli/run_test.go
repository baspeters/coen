package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/metrics"
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

	lvl, err := config.EdgeLogLevel(cfgPath)
	if err != nil {
		t.Fatalf("edgeLevel: %v", err)
	}
	if lvl != "debug" {
		t.Fatalf("edgeLevel = %q, want %q", lvl, "debug")
	}
}

func TestEdgeLevelMissingConfig(t *testing.T) {
	if _, err := config.EdgeLogLevel("/no/such/edge.yaml"); err == nil {
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

	lvl, err := config.AgentLogLevel(cfgPath)
	if err != nil {
		t.Fatalf("agentLevel: %v", err)
	}
	if lvl != "warn" {
		t.Fatalf("agentLevel = %q, want %q", lvl, "warn")
	}
}

func TestAgentLevelMissingConfig(t *testing.T) {
	if _, err := config.AgentLogLevel("/no/such/agent.yaml"); err == nil {
		t.Fatal("expected error for missing agent config")
	}
}

// fakeRunner is a stub runner used to drive runDaemon in tests. With ready
// and stop left nil, Run returns err immediately. When set, Run closes ready
// right after being invoked (so a test knows runDaemon has reached the point
// of launching its admin-server goroutine) and then blocks until stop is
// closed before returning err; this lets a test give the admin goroutine as
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

	if err := runDaemon(log, lv, state, daemonOpts{}, reload, fakeRunner{err: wantErr}); !errors.Is(err, wantErr) {
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
		done <- runDaemon(log, lv, state, daemonOpts{socket: sock}, reload, fakeRunner{err: wantErr, ready: ready, stop: stop})
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

// TestEdgeCmdBindFailure drives newEdgeCmd's full body: config load, logger
// setup, edge.New, then runDaemon calling into edge.Run, by pointing
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

func TestServeDaemonServesMetrics(t *testing.T) {
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	reload := func() (string, error) { return "info", nil }

	ready, stop := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(context.Background(), log, lv, obs.NewState("agent"), "", metricsBinding{ln: ln}, make(chan os.Signal), reload, fakeRunner{ready: ready, stop: stop})
	}()
	<-ready

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		close(stop)
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), `coen_build_info{role="agent"`) {
		close(stop)
		t.Fatalf("unexpected metrics body:\n%s", body)
	}

	close(stop)
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon = %v", err)
	}
	// serveDaemon waits for the metrics server to shut down before returning.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("metrics listener still open after serveDaemon returned")
	}
}

func TestRunDaemonMetricsBindFailure(t *testing.T) {
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	reload := func() (string, error) { return "info", nil }
	// A port held by another service (not a coen edge) is fatal.
	foreign, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	go func() {
		for {
			c, err := foreign.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\ngo_goroutines 7\n"))
			_ = c.Close()
		}
	}()
	err = runDaemon(log, lv, obs.NewState("edge"), daemonOpts{metricsAddr: foreign.Addr().String()}, reload, fakeRunner{err: errors.New("runner must not start")})
	if err == nil || !strings.Contains(err.Error(), "metrics listen") {
		t.Fatalf("a foreign holder must be fatal, got %v", err)
	}
	// An address this host does not have is a configuration error: fatal.
	err = runDaemon(log, lv, obs.NewState("edge"), daemonOpts{metricsAddr: "192.0.2.123:9464"}, reload, fakeRunner{err: errors.New("runner must not start")})
	if err == nil || !strings.Contains(err.Error(), "metrics listen") {
		t.Fatalf("want a metrics listen error, got %v", err)
	}
}

// A busy metrics port (a previous instance still draining) does not stop the
// daemon: it serves traffic and claims the port once it is released.
func TestServeDaemonClaimsBusyMetricsPortLater(t *testing.T) {
	old := metricsRetryInterval
	metricsRetryInterval = 20 * time.Millisecond
	defer func() { metricsRetryInterval = old }()
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// The predecessor: a draining coen edge serving metrics on the port.
	pred, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pred.Addr().String()
	predState := obs.NewState("edge")
	predState.SetDraining()
	predCtx, stopPred := context.WithCancel(context.Background())
	predDone := make(chan struct{})
	go func() { _ = metrics.Serve(predCtx, pred, metrics.Handler(predState, "old"), log); close(predDone) }()

	ready, stop := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(context.Background(), log, lv, obs.NewState("edge"), "", metricsBinding{retryAddr: addr}, make(chan os.Signal), func() (string, error) { return "info", nil }, fakeRunner{ready: ready, stop: stop})
	}()
	<-ready                            // the daemon runs although the metrics port is taken
	time.Sleep(100 * time.Millisecond) // several retries while the predecessor drains
	stopPred()
	<-predDone
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "coen_draining 0") {
				break
			}
		}
		if time.Now().After(deadline) {
			close(stop)
			t.Fatalf("metrics never came up after the port was freed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon = %v", err)
	}
}

// If the daemon stops before the busy port frees up, the retry ends with it.
func TestServeDaemonStopsRetryingOnShutdown(t *testing.T) {
	old := metricsRetryInterval
	metricsRetryInterval = 20 * time.Millisecond
	defer func() { metricsRetryInterval = old }()
	log, lv, _ := obs.NewLogger("info", "text", io.Discard)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(context.Background(), log, lv, obs.NewState("edge"), "", metricsBinding{retryAddr: busy.Addr().String()}, make(chan os.Signal), func() (string, error) { return "info", nil }, fakeRunner{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveDaemon = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveDaemon kept waiting on the busy metrics port after Run returned")
	}
}

// drainRunner models a daemon's Run: it blocks until ctx is cancelled (the
// shutdown signal), then "drains" by calling during() before returning.
type drainRunner struct {
	ready  chan struct{}
	during func()
}

func (d drainRunner) Run(ctx context.Context) error {
	close(d.ready)
	<-ctx.Done()
	d.during()
	return nil
}

// The metrics endpoint and admin socket must stay up after the shutdown signal
// while the daemon drains, and close only once Run has returned.
func TestServeDaemonSideServersOutliveSignal(t *testing.T) {
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "a.sock")

	var metricsDuringDrain, statusDuringDrain error
	r := drainRunner{ready: make(chan struct{}), during: func() {
		var resp *http.Response
		resp, metricsDuringDrain = http.Get("http://" + addr + "/metrics")
		if resp != nil {
			_ = resp.Body.Close()
		}
		_, statusDuringDrain = admin.Status(sock)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(ctx, log, lv, obs.NewState("edge"), sock, metricsBinding{ln: ln}, make(chan os.Signal), func() (string, error) { return "info", nil }, r)
	}()
	<-r.ready
	// Wait until both side servers are up before signalling shutdown.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, sErr := admin.Status(sock)
		resp, mErr := http.Get("http://" + addr + "/metrics")
		if resp != nil {
			_ = resp.Body.Close()
		}
		if sErr == nil && mErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("side servers never came up: status=%v metrics=%v", sErr, mErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel() // the shutdown signal
	if err := <-done; err != nil {
		t.Fatalf("serveDaemon = %v", err)
	}
	if metricsDuringDrain != nil {
		t.Fatalf("metrics unavailable during drain: %v", metricsDuringDrain)
	}
	if statusDuringDrain != nil {
		t.Fatalf("admin status unavailable during drain: %v", statusDuringDrain)
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("metrics listener still open after serveDaemon returned")
	}
}

// A port held by a coen daemon of the same role (a predecessor still
// draining) lets the daemon start; runDaemon then returns the runner's result.
func TestRunDaemonWaitsForSameRolePredecessor(t *testing.T) {
	old := metricsRetryInterval
	metricsRetryInterval = 20 * time.Millisecond
	defer func() { metricsRetryInterval = old }()
	log, lv, err := obs.NewLogger("info", "text", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	pred, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pred.Close()
	predCtx, stopPred := context.WithCancel(context.Background())
	defer stopPred()
	predState := obs.NewState("edge")
	go func() { _ = metrics.Serve(predCtx, pred, metrics.Handler(predState, "old"), log) }()
	wantErr := errors.New("runner ran")
	// A live (not draining) same-role instance is a real conflict.
	err = runDaemon(log, lv, obs.NewState("edge"), daemonOpts{metricsAddr: pred.Addr().String()}, func() (string, error) { return "info", nil }, fakeRunner{err: wantErr})
	if err == nil || !strings.Contains(err.Error(), "metrics listen") {
		t.Fatalf("a live same-role instance must be fatal, got %v", err)
	}
	predState.SetDraining()
	err = runDaemon(log, lv, obs.NewState("edge"), daemonOpts{metricsAddr: pred.Addr().String()}, func() (string, error) { return "info", nil }, fakeRunner{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("the daemon should start next to a same-role predecessor, got %v", err)
	}
	// The other role's endpoint on the port is a real conflict.
	err = runDaemon(log, lv, obs.NewState("agent"), daemonOpts{metricsAddr: pred.Addr().String()}, func() (string, error) { return "info", nil }, fakeRunner{err: wantErr})
	if err == nil || !strings.Contains(err.Error(), "metrics listen") {
		t.Fatalf("another role's endpoint must be fatal, got %v", err)
	}
}

// The wait ends, with metrics.listen_failed, once the holder is no longer a
// draining coen daemon of the same role (here a plain listener).
func TestMetricsTakeoverGivesUpWhenHolderIsNotDraining(t *testing.T) {
	old := metricsRetryInterval
	metricsRetryInterval = 10 * time.Millisecond
	defer func() { metricsRetryInterval = old }()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: &buf}, nil))
	m := metricsBinding{retryAddr: busy.Addr().String()}
	done := make(chan bool, 1)
	go func() { _, ok := m.await(context.Background(), log, "edge"); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("await must give up when the holder is not a draining coen daemon")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("await did not give up")
	}
	if !strings.Contains(buf.String(), "metrics.listen_failed") {
		t.Fatalf("missing metrics.listen_failed log: %s", buf.String())
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Shutdown is not held up by a probe in flight against a holder that accepts
// connections but never answers.
func TestMetricsAwaitStopsPromptlyDuringProbe(t *testing.T) {
	old := metricsRetryInterval
	metricsRetryInterval = 10 * time.Millisecond
	defer func() { metricsRetryInterval = old }()
	silent, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never answers
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	log, _, _ := obs.NewLogger("info", "text", io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _, _ = metricsBinding{retryAddr: silent.Addr().String()}.await(ctx, log, "edge"); close(done) }()
	time.Sleep(100 * time.Millisecond) // the probe is now waiting on the silent holder
	start := time.Now()
	cancel()
	select {
	case <-done:
		if d := time.Since(start); d > time.Second {
			t.Fatalf("await took %v to stop after cancel", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("await did not stop after cancel")
	}
}
