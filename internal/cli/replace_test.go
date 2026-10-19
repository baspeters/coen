package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

type fakeSuccessor struct {
	preparedErr error
	mu          sync.Mutex
	went        bool
	stopped     bool
	exited      chan struct{}
}

func (f *fakeSuccessor) WaitPrepared(time.Duration) error { return f.preparedErr }
func (f *fakeSuccessor) Go() error                        { f.mu.Lock(); f.went = true; f.mu.Unlock(); return nil }
func (f *fakeSuccessor) Pid() int                         { return 4242 }
func (f *fakeSuccessor) Stop()                            { f.mu.Lock(); f.stopped = true; f.mu.Unlock() }
func (f *fakeSuccessor) Exited() <-chan struct{} {
	if f.exited == nil {
		f.exited = make(chan struct{})
	}
	return f.exited
}

type fakeAgent struct {
	onRetired func()
	late      bool // already stepped aside
}

func (f *fakeAgent) SetOnRetired(fn func()) bool {
	if f.late {
		return false
	}
	f.onRetired = fn
	return true
}

func testReplacer(s successor, spawnErr error) (*replacer, *fakeAgent, *bool, *[]string, *bytes.Buffer) {
	var buf bytes.Buffer
	cancelled := false
	var notes []string
	a := &fakeAgent{}
	r := &replacer{
		log:    slog.New(slog.NewTextHandler(&buf, nil)),
		state:  obs.NewState("agent"),
		agent:  a,
		ctx:    context.Background(),
		cancel: func() { cancelled = true },
		spawn:  func() (successor, error) { return s, spawnErr },
		notify: func(m string) (bool, error) { notes = append(notes, m); return true, nil },
	}
	return r, a, &cancelled, &notes, &buf
}

func TestNewReplacerNeedsNotify(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if newReplacer(context.Background(), nil, nil, &fakeAgent{}, func() {}) != nil {
		t.Fatal("without a Type=notify unit the agent cannot be replaced")
	}
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	if newReplacer(context.Background(), nil, nil, &fakeAgent{}, func() {}) == nil {
		t.Fatal("under a Type=notify unit it can")
	}
}

func TestReplaceHandsOver(t *testing.T) {
	s := &fakeSuccessor{}
	r, a, cancelled, notes, _ := testReplacer(s, nil)
	if err := r.replace(); err != nil {
		t.Fatal(err)
	}
	if !*cancelled || !r.state.Detail().Draining {
		t.Fatal("the running agent must start its graceful shutdown")
	}
	if a.onRetired == nil || s.went {
		t.Fatal("the go-ahead waits until the edge has retired this agent")
	}
	a.onRetired()
	if !s.went || len(*notes) != 1 || (*notes)[0] != "MAINPID=4242" {
		t.Fatalf("went %v, notes %v", s.went, *notes)
	}
	if err := r.replace(); err == nil || !strings.Contains(err.Error(), "already under way") {
		t.Fatalf("a second reload while one is under way: %v", err)
	}
}

// A replacement that does not come up leaves the running agent as it is.
func TestReplaceSuccessorFails(t *testing.T) {
	for name, c := range map[string]struct {
		s        successor
		spawnErr error
		want     string
	}{
		"not prepared": {&fakeSuccessor{preparedErr: errors.New("the replacement exited before it was ready: exit status 1")}, nil, "exited before it was ready"},
		"no spawn":     {nil, errors.New("no such file"), "start the replacement: no such file"},
	} {
		r, a, cancelled, _, _ := testReplacer(c.s, c.spawnErr)
		if err := r.replace(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v", name, err)
		}
		if *cancelled || a.onRetired != nil || r.state.Detail().Draining {
			t.Fatalf("%s: the running agent must carry on", name)
		}
		if r.busy.Load() {
			t.Fatalf("%s: a later reload must be possible", name)
		}
	}
}

func TestSpawnSelfFindsTheBinary(t *testing.T) {
	// The test binary, run with no tests, exits at once; only the start is
	// checked here (handoff covers the protocol).
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{old[0], "-test.run=^$"}
	s, err := spawnSelf()
	if err != nil || s.Pid() <= 0 {
		t.Fatalf("%v %v", s, err)
	}
	_ = s.WaitPrepared(5 * time.Second) // it exits without preparing
}

func TestNotifyReady(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	t.Setenv("NOTIFY_SOCKET", "")
	notifyReady(log)
	if buf.Len() != 0 {
		t.Fatalf("no socket: nothing to say, got %q", buf.String())
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "gone.sock"))
	notifyReady(log)
	if !strings.Contains(buf.String(), "systemd.notify_error") {
		t.Fatalf("got %q", buf.String())
	}
}

type failingSuccessor struct{ fakeSuccessor }

func (*failingSuccessor) Go() error { return errors.New("broken pipe") }

// A go-ahead the replacement cannot read (it is exiting) is logged; systemd,
// already watching it, restarts the service if it goes.
func TestReplaceGoAheadFails(t *testing.T) {
	r, a, _, notes, buf := testReplacer(&failingSuccessor{}, nil)
	if err := r.replace(); err != nil {
		t.Fatal(err)
	}
	a.onRetired()
	if len(*notes) != 1 || !strings.Contains(buf.String(), "reload.go_error") || r.failed() != nil {
		t.Fatalf("notes %v, log %s", *notes, buf.String())
	}
}

// systemd cannot be told: the replacement is stopped, and this agent exits
// non-zero so that systemd restarts the service.
func TestReplaceNotifyFails(t *testing.T) {
	s := &fakeSuccessor{}
	r, a, _, _, buf := testReplacer(s, nil)
	r.notify = func(string) (bool, error) { return true, errors.New("no systemd") }
	if err := r.replace(); err != nil {
		t.Fatal(err)
	}
	a.onRetired()
	if s.went || !s.stopped || r.failed() == nil || !strings.Contains(buf.String(), "reload.notify_error") {
		t.Fatalf("went %v stopped %v failed %v log %s", s.went, s.stopped, r.failed(), buf.String())
	}
}

// The replacement died before the handover: no MAINPID, no go-ahead, and a
// non-zero exit.
func TestReplaceSuccessorDiesBeforeTheHandover(t *testing.T) {
	s := &fakeSuccessor{exited: make(chan struct{})}
	close(s.exited)
	r, a, _, notes, buf := testReplacer(s, nil)
	if err := r.replace(); err != nil {
		t.Fatal(err)
	}
	a.onRetired()
	if s.went || len(*notes) != 0 || r.failed() == nil || !strings.Contains(buf.String(), "reload.successor_gone") {
		t.Fatalf("went %v notes %v failed %v", s.went, *notes, r.failed())
	}
	var none *replacer
	if none.failed() != nil {
		t.Fatal("no replacer: nothing failed")
	}
}

// A shutdown that began first, or while the replacement was starting, or an
// agent that has already stepped aside: the replacement is stopped and this
// agent carries on leaving as it was.
func TestReplaceDuringShutdown(t *testing.T) {
	r, _, cancelled, _, _ := testReplacer(&fakeSuccessor{}, nil)
	ctx, stop := context.WithCancel(context.Background())
	stop()
	r.ctx = ctx
	if err := r.replace(); err == nil || !strings.Contains(err.Error(), "already shutting down") || *cancelled {
		t.Fatalf("got %v", err)
	}

	s := &fakeSuccessor{}
	r, _, _, _, _ = testReplacer(s, nil)
	ctx, stop = context.WithCancel(context.Background())
	r.ctx = ctx
	r.spawn = func() (successor, error) { stop(); return s, nil } // the SIGTERM lands meanwhile
	if err := r.replace(); err == nil || !strings.Contains(err.Error(), "while its replacement started") || !s.stopped || r.busy.Load() {
		t.Fatalf("got %v, stopped %v", err, s.stopped)
	}

	s = &fakeSuccessor{}
	r, a, cancelled, _, _ := testReplacer(s, nil)
	a.late = true
	if err := r.replace(); err == nil || !strings.Contains(err.Error(), "already stepped aside") || !s.stopped || *cancelled {
		t.Fatalf("got %v", err)
	}
}

func TestSpawnSelfWithoutExecutable(t *testing.T) {
	defer func(old func() (string, error)) { executable = old }(executable)
	executable = func() (string, error) { return "", errors.New("no /proc") }
	if _, err := spawnSelf(); err == nil {
		t.Fatal("want an error")
	}
}
