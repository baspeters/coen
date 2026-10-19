package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/baspeters/coen/internal/handoff"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/sdnotify"
)

// Seamless agent reload. Under a systemd unit with Type=notify, SIGHUP
// (`systemctl reload coen-agent`) replaces the agent process instead of only
// re-reading the log level: the running agent starts a new one with the same
// binary path (so an upgraded binary is picked up) and arguments, which loads
// its config and certificates and reports back. The running agent then asks
// the edge to take it out of its pool and, once the edge has, tells systemd
// that the new process is the service's main process and gives it the
// go-ahead. The new process connects (the edge holds requests meanwhile, see
// agent_wait) while the old one finishes its in-flight requests and exits.
// A new process that fails to start (a broken config) is reported, and the
// running agent carries on.

// preparedWait bounds a replacement's start-up: loading the config and
// certificates takes well under a second.
const preparedWait = 30 * time.Second

// goAheadWait bounds a replacement's wait for the go-ahead: the edge's drain
// acknowledgement takes at most a few seconds.
const goAheadWait = 60 * time.Second

// successor is the part of handoff.Successor a replacement needs.
type successor interface {
	WaitPrepared(timeout time.Duration) error
	Go() error
	Pid() int
	Exited() <-chan struct{}
	Stop()
}

// agentRetirer is the part of agent.Agent a replacement needs.
type agentRetirer interface {
	SetOnRetired(func()) bool
}

// replacer replaces the running agent on SIGHUP (see above).
type replacer struct {
	log    *slog.Logger
	state  *obs.State
	agent  agentRetirer
	ctx    context.Context    // the running agent's: done once it shuts down
	cancel context.CancelFunc // starts the running agent's graceful shutdown
	spawn  func() (successor, error)
	notify func(string) (bool, error)
	busy   atomic.Bool // a replacement is under way
	// handoverFailed records a replacement that could not take over after
	// this agent had already stepped aside (see failed).
	handoverFailed atomic.Bool
}

// newReplacer returns the replacer for a, or nil when this agent cannot be
// replaced: not under a Type=notify systemd unit, which is what lets the new
// process become the service's main process.
func newReplacer(ctx context.Context, log *slog.Logger, state *obs.State, a agentRetirer, cancel context.CancelFunc) *replacer {
	if !sdnotify.Available() {
		return nil
	}
	return &replacer{log: log, state: state, agent: a, ctx: ctx, cancel: cancel, spawn: spawnSelf, notify: sdnotify.Notify}
}

// failed reports a handover that went wrong after this agent had stepped
// aside: its replacement died, or systemd could not be told about it. The
// daemon then exits non-zero, so that systemd restarts the service rather
// than leave it with no agent.
func (r *replacer) failed() error {
	if r != nil && r.handoverFailed.Load() {
		return errors.New("the replacement did not take over; exiting so that systemd restarts the agent")
	}
	return nil
}

// executable finds this binary; tests replace it.
var executable = os.Executable

// spawnSelf starts this binary again with the same arguments.
func spawnSelf() (successor, error) {
	exe, err := executable() // the new binary if it was replaced on disk
	if err != nil {
		return nil, err
	}
	return handoff.Start(exe, os.Args[1:], os.Environ())
}

// replace replaces the running agent, or reports why it could not, leaving it
// running. Only one replacement runs at a time.
func (r *replacer) replace() error {
	if r.ctx.Err() != nil {
		return errors.New("this agent is already shutting down")
	}
	if !r.busy.CompareAndSwap(false, true) {
		return errors.New("a replacement is already under way")
	}
	r.log.Info("reload.start", "how", "starting a replacement process")
	s, err := r.spawn()
	if err != nil {
		r.busy.Store(false)
		return fmt.Errorf("start the replacement: %w", err)
	}
	if err := s.WaitPrepared(preparedWait); err != nil {
		r.busy.Store(false)
		return err // its own error output says why, in the same log
	}
	pid := s.Pid()
	// A shutdown that began while the replacement was starting has already
	// passed the moment to hand over: this agent leaves as it would have,
	// without it.
	abort := func(why string) error {
		s.Stop()
		r.busy.Store(false)
		return errors.New(why)
	}
	if r.ctx.Err() != nil {
		return abort("this agent began shutting down while its replacement started")
	}
	r.log.Info("reload.successor_ready", "pid", pid, "next", "handing over once the edge has taken this agent out of its pool")
	if !r.agent.SetOnRetired(func() { r.handOver(s, pid) }) {
		return abort("this agent had already stepped aside")
	}
	r.state.SetDraining()
	r.cancel()
	return nil
}

// handOver makes s the service's main process and gives it the go-ahead,
// once the edge has taken this agent out of its pool.
func (r *replacer) handOver(s successor, pid int) {
	select {
	case <-s.Exited():
		r.handoverFailed.Store(true)
		r.log.Error("reload.successor_gone", "pid", pid, "impact", "no agent will be left: exiting non-zero so that systemd restarts it")
		return
	default:
	}
	// systemd first: once the new process has the go-ahead this one may
	// exit at any moment, and systemd must not see the service's main
	// process gone.
	if _, err := r.notify(fmt.Sprintf("MAINPID=%d", pid)); err != nil {
		r.handoverFailed.Store(true)
		s.Stop()
		r.log.Error("reload.notify_error", "error", err.Error(), "impact", "systemd still sees this process as the agent: exiting non-zero so that it restarts the service")
		return
	}
	if err := s.Go(); err != nil {
		// Its pipe broke: it is exiting, and systemd, now watching it,
		// restarts the service.
		r.log.Warn("reload.go_error", "pid", pid, "error", err.Error())
	}
	r.log.Info("reload.handed_over", "pid", pid)
}

// awaitTurn is a replacement's side of the handoff: when this process was
// started by a running agent, tell it that this one is ready and wait for
// its go-ahead before going on to bind listeners and connect.
func awaitTurn(log *slog.Logger) error {
	p, err := handoff.FromEnv()
	if err != nil || p == nil {
		return err
	}
	if err := p.Prepared(); err != nil {
		return fmt.Errorf("report to the process being replaced: %w", err)
	}
	if err := p.WaitGo(goAheadWait); err != nil {
		log.Warn("reload.no_go_ahead", "error", err.Error(), "action", "starting anyway")
		return nil
	}
	log.Info("reload.taking_over")
	return nil
}

// notifyReady tells systemd the daemon has started, for Type=notify units.
func notifyReady(log *slog.Logger) {
	if _, err := sdnotify.Notify("READY=1"); err != nil {
		log.Warn("systemd.notify_error", "error", err.Error())
	}
}
