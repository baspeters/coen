package handoff

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the successor: with COEN_HANDOFF_ROLE set it
// plays one, as told, instead of running the tests.
func TestMain(m *testing.M) {
	if role := os.Getenv("COEN_HANDOFF_ROLE"); role != "" {
		os.Exit(successor(role))
	}
	os.Exit(m.Run())
}

func successor(role string) int {
	p, err := FromEnv()
	if err != nil || p == nil {
		fmt.Fprintln(os.Stderr, "no predecessor:", err)
		return 2
	}
	switch role {
	case "fail":
		fmt.Fprintln(os.Stderr, "config: broken")
		return 3
	case "hang":
		time.Sleep(time.Minute)
		return 0
	case "garble":
		_, _ = p.prepared.Write([]byte{'X'})
		time.Sleep(time.Minute)
		return 0
	}
	if err := p.Prepared(); err != nil {
		return 4
	}
	switch err := p.WaitGo(5 * time.Second); {
	case role == "go" && err == nil:
		return 0 // got the go-ahead
	case role == "orphan" && err == ErrNoGoAhead:
		return 0 // the predecessor went away: carry on
	}
	return 5
}

func start(t *testing.T, role string) *Successor {
	t.Helper()
	s, err := Start(os.Args[0], []string{"-test.run=^$"}, append(os.Environ(), "COEN_HANDOFF_ROLE="+role))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func exitCode(t *testing.T, s *Successor) int {
	t.Helper()
	select {
	case <-s.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("the successor did not exit")
	}
	return s.cmd.ProcessState.ExitCode()
}

func TestHandoff(t *testing.T) {
	s := start(t, "go")
	if s.Pid() <= 0 {
		t.Fatal("no pid")
	}
	if err := s.WaitPrepared(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Go(); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, s); code != 0 {
		t.Fatalf("the successor exited %d", code)
	}
}

// A successor that fails before it is prepared leaves the predecessor in
// charge, with the reason in hand.
func TestHandoffSuccessorFails(t *testing.T) {
	s := start(t, "fail")
	err := s.WaitPrepared(5 * time.Second)
	if err == nil || !strings.Contains(err.Error(), "exited before it was ready") || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("got %v", err)
	}
}

func TestHandoffSuccessorSaysSomethingElse(t *testing.T) {
	s := start(t, "garble")
	if err := s.WaitPrepared(5 * time.Second); err == nil || !strings.Contains(err.Error(), "unexpected handoff message") {
		t.Fatalf("got %v", err)
	}
	<-s.Exited() // it was stopped
}

func TestHandoffSuccessorHangs(t *testing.T) {
	s := start(t, "hang")
	start := time.Now()
	err := s.WaitPrepared(300 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "not ready within 300ms") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the wait overran")
	}
	<-s.Exited() // it was stopped
}

// A successor whose predecessor goes away before the go-ahead starts anyway.
func TestHandoffPredecessorGone(t *testing.T) {
	s := start(t, "orphan")
	if err := s.WaitPrepared(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	_ = s.goAhead.Close() // as if this process had exited
	if code := exitCode(t, s); code != 0 {
		t.Fatalf("the successor exited %d", code)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(envFDs, "")
	_ = os.Unsetenv(envFDs)
	if p, err := FromEnv(); p != nil || err != nil {
		t.Fatalf("started normally: %v %v", p, err)
	}
	for _, v := range []string{"3", "3,x", "1,2", ""} {
		t.Setenv(envFDs, v)
		if _, err := FromEnv(); err == nil {
			t.Fatalf("%q: want an error", v)
		}
		if _, still := os.LookupEnv(envFDs); still {
			t.Fatalf("%q: the variable must be taken out", v)
		}
	}
}

func TestStartFails(t *testing.T) {
	if _, err := Start("/nonexistent/coen", nil, nil); err == nil {
		t.Fatal("a missing binary must fail")
	}
}

func TestWaitGoTimesOut(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	p := &Predecessor{goAhead: r}
	if err := p.WaitGo(100 * time.Millisecond); err != ErrNoGoAhead {
		t.Fatalf("got %v", err)
	}
}

func TestStartWithoutPipes(t *testing.T) {
	defer func(old func() (*os.File, *os.File, error)) { pipe = old }(pipe)
	for fail := 1; fail <= 2; fail++ {
		calls := 0
		pipe = func() (*os.File, *os.File, error) {
			if calls++; calls == fail {
				return nil, nil, os.ErrClosed
			}
			return os.Pipe()
		}
		if _, err := Start(os.Args[0], nil, nil); err == nil {
			t.Fatalf("pipe %d failing: want an error", fail)
		}
	}
}

func TestStop(t *testing.T) {
	s := start(t, "go")
	if err := s.WaitPrepared(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	s.Stop() // before the go-ahead
	select {
	case <-s.Exited():
	default:
		t.Fatal("Stop returns once it has exited")
	}
	s.Stop() // again: nothing left to stop
}
