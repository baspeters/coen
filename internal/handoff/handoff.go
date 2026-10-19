// Package handoff lets a running daemon start its replacement and hand over
// to it without a gap.
//
// The running process (the predecessor) starts the new one (the successor)
// with two pipes. The successor loads its config and certificates and
// reports that it is prepared, then waits for the go-ahead before it does
// anything visible to the outside, such as connecting to the edge or
// binding its listeners. The predecessor gives the go-ahead once it has
// stepped aside, and then finishes its in-flight work and exits. If the
// successor fails before it is prepared (a broken config, say), the
// predecessor carries on as if nothing happened.
package handoff

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// envFDs names the environment variable that tells a successor which file
// descriptors carry the handoff: the go-ahead it reads, then the pipe it
// reports on.
const envFDs = "COEN_HANDOFF_FDS"

// Messages on the pipes, one byte each.
const (
	msgPrepared = 'P'
	msgGo       = 'G'
)

// pipe makes a pipe; tests replace it.
var pipe = os.Pipe

// Successor is a replacement started by Start, seen from its predecessor.
type Successor struct {
	cmd      *exec.Cmd
	prepared *os.File // read: the successor reports on it
	goAhead  *os.File // write: the go-ahead
	exited   chan struct{}
	waitErr  error // set before exited is closed
}

// Start starts exe with args and env (plus the handoff file descriptors),
// sharing this process's standard output and error.
func Start(exe string, args, env []string) (*Successor, error) {
	goR, goW, err := pipe()
	if err != nil {
		return nil, err
	}
	prepR, prepW, err := pipe()
	if err != nil {
		_ = goR.Close()
		_ = goW.Close()
		return nil, err
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(env, envFDs+"=3,4") // ExtraFiles start at 3
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{goR, prepW}
	err = cmd.Start()
	// The child has its own copies now; ours would keep the pipes open.
	_ = goR.Close()
	_ = prepW.Close()
	if err != nil {
		_ = goW.Close()
		_ = prepR.Close()
		return nil, err
	}
	s := &Successor{cmd: cmd, prepared: prepR, goAhead: goW, exited: make(chan struct{})}
	go func() {
		s.waitErr = cmd.Wait()
		close(s.exited)
	}()
	return s, nil
}

// Pid is the successor's process id.
func (s *Successor) Pid() int { return s.cmd.Process.Pid }

// WaitPrepared waits up to timeout for the successor to report that it is
// prepared. An error means it is not coming: it exited (its own error output
// says why), or it did not report in time and has been stopped.
func (s *Successor) WaitPrepared(timeout time.Duration) error {
	got := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, err := io.ReadFull(s.prepared, b)
		switch {
		case err != nil:
			got <- err
		case b[0] != msgPrepared:
			got <- fmt.Errorf("unexpected handoff message %q", b[0])
		default:
			got <- nil
		}
	}()
	select {
	case err := <-got:
		if err == nil {
			return nil
		}
		// The pipe closed (it exited), or it said something else: either way
		// it is not taking over, so make sure it is gone.
		_ = s.cmd.Process.Kill()
		<-s.exited
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("the replacement exited before it was ready: %v", s.waitErr)
		}
		return fmt.Errorf("the replacement was stopped: %w", err)
	case <-time.After(timeout):
		_ = s.cmd.Process.Kill()
		<-s.exited
		return fmt.Errorf("the replacement was not ready within %s and was stopped", timeout)
	}
}

// Go gives the successor the go-ahead.
func (s *Successor) Go() error {
	defer s.goAhead.Close()
	_, err := s.goAhead.Write([]byte{msgGo})
	return err
}

// Stop ends the successor, if it is still running, and waits for it to exit.
func (s *Successor) Stop() {
	_ = s.cmd.Process.Kill()
	<-s.exited
}

// Exited is closed when the successor exits.
func (s *Successor) Exited() <-chan struct{} { return s.exited }

// Predecessor is the process this one replaces, seen from the successor.
type Predecessor struct {
	goAhead  *os.File
	prepared *os.File
}

// FromEnv returns the predecessor this process was started by, or nil when
// it was started normally. It takes the handoff out of the environment, so
// a successor this process starts later gets its own.
func FromEnv() (*Predecessor, error) {
	v, ok := os.LookupEnv(envFDs)
	if !ok {
		return nil, nil
	}
	_ = os.Unsetenv(envFDs)
	parts := strings.Split(v, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%s=%q: want two file descriptors", envFDs, v)
	}
	fds := make([]uintptr, 2)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 3 {
			return nil, fmt.Errorf("%s=%q: bad file descriptor %q", envFDs, v, p)
		}
		fds[i] = uintptr(n)
	}
	return &Predecessor{goAhead: os.NewFile(fds[0], "handoff-go"), prepared: os.NewFile(fds[1], "handoff-prepared")}, nil
}

// Prepared tells the predecessor that this process is ready to take over.
func (p *Predecessor) Prepared() error {
	defer p.prepared.Close()
	_, err := p.prepared.Write([]byte{msgPrepared})
	return err
}

// ErrNoGoAhead reports a predecessor that went away, or took longer than
// the wait, without giving the go-ahead; the successor carries on anyway, as
// a normal start.
var ErrNoGoAhead = errors.New("no go-ahead from the process being replaced")

// WaitGo waits up to timeout for the go-ahead. ErrNoGoAhead means it did not
// come; the caller then starts anyway.
func (p *Predecessor) WaitGo(timeout time.Duration) error {
	defer p.goAhead.Close()
	got := make(chan bool, 1)
	go func() {
		b := make([]byte, 1)
		_, err := io.ReadFull(p.goAhead, b)
		got <- err == nil && b[0] == msgGo
	}()
	select {
	case ok := <-got:
		if ok {
			return nil
		}
		return ErrNoGoAhead
	case <-time.After(timeout):
		return ErrNoGoAhead
	}
}
