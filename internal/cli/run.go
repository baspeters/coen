package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/metrics"
	"github.com/baspeters/coen/internal/netx"
	"github.com/baspeters/coen/internal/obs"
	"github.com/spf13/cobra"
)

func init() {
	register(newEdgeCmd)
	register(newAgentCmd)
}

type runner interface {
	Run(ctx context.Context) error
}

func newEdgeCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "edge",
		Short: "Run the public edge",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadEdge(cfgPath)
			if err != nil {
				return err
			}
			cfg.Version = Version
			log, lv, err := obs.NewLogger(cfg.Log.Level, cfg.Log.Format, os.Stderr)
			if err != nil {
				return err
			}
			state := obs.NewState("edge")
			e, err := edge.New(cfg, log, state)
			if err != nil {
				return err
			}
			return runDaemon(log, lv, state, daemonOpts{socket: cfg.Admin.Socket, metricsAddr: cfg.Metrics.Listen}, func() (string, error) { return config.EdgeLogLevel(cfgPath) }, e)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/coen/edge.yaml", "config file")
	return cmd
}

func newAgentCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the private agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadAgent(cfgPath)
			if err != nil {
				return err
			}
			cfg.Version = Version
			log, lv, err := obs.NewLogger(cfg.Log.Level, cfg.Log.Format, os.Stderr)
			if err != nil {
				return err
			}
			state := obs.NewState("agent")
			a, err := agent.New(cfg, log, state)
			if err != nil {
				return err
			}
			// Started by a running agent to replace it: wait for the go-ahead
			// before binding anything or connecting (see replace.go). systemd
			// may already send a reload to this process meanwhile; ignore it
			// until runDaemon handles SIGHUP, rather than die of it.
			signal.Ignore(syscall.SIGHUP)
			if err := awaitTurn(log); err != nil {
				return err
			}
			return runDaemon(log, lv, state, daemonOpts{socket: cfg.Admin.Socket, metricsAddr: cfg.Metrics.Listen, agent: a}, func() (string, error) { return config.AgentLogLevel(cfgPath) }, a)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/coen/agent.yaml", "config file")
	return cmd
}

// daemonOpts are the side-server settings around a daemon's Run.
type daemonOpts struct {
	socket      string       // admin socket path; empty disables it
	metricsAddr string       // metrics.listen; empty disables metrics
	agent       agentRetirer // the agent, which SIGHUP can replace (see replace.go); nil for the edge
}

// runDaemon runs r with the admin socket, the optional metrics endpoint, and
// SIGHUP log-level reload around it, until SIGINT/SIGTERM or r returns.
func runDaemon(log *slog.Logger, lv *slog.LevelVar, state *obs.State, opts daemonOpts, reloadLevel func() (string, error), r runner) error {
	// Install the signal handlers first, so a SIGHUP or SIGTERM that arrives
	// during the startup work below (which may probe a busy metrics port) is
	// queued for the daemon instead of hitting the default action.
	//
	// The shutdown signal marks the state as draining before it cancels ctx,
	// so the metrics endpoint reports coen_draining 1 before the daemon starts
	// closing its listeners and a replacement can bind them.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(term)
	go func() {
		select {
		case <-term:
			state.SetDraining()
			cancel()
		case <-ctx.Done():
		}
	}()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	// Bind the metrics listener before starting, so a bad address, a missing
	// permission, or a port held by another service fails the daemon at
	// startup like any other listener. The one exception is a port held by a
	// coen daemon of the same role: a previous instance that is still draining
	// keeps its metrics endpoint until it exits, so this daemon starts and
	// claims the port once it is free.
	m := metricsBinding{}
	if opts.metricsAddr != "" {
		ln, err := net.Listen("tcp", opts.metricsAddr)
		switch {
		case err == nil:
			m.ln = ln
		case netx.IsAddrInUse(err) && drainingPredecessor(ctx, opts.metricsAddr, state.Role()):
			// Wait for as long as the predecessor keeps draining; its own
			// drain_timeout bounds that, whatever ours is.
			m.retryAddr = opts.metricsAddr
			log.Warn("metrics.listen_busy", "address", opts.metricsAddr, "reason", "held by a draining coen "+state.Role()+" (a previous instance shutting down)", "action", "claiming the port once it is free")
		default:
			return fmt.Errorf("metrics listen: %w", err)
		}
	}
	var rep *replacer
	if opts.agent != nil {
		rep = newReplacer(ctx, log, state, opts.agent, cancel)
	}
	if err := serveDaemon(ctx, log, lv, state, opts.socket, m, hup, reloadLevel, rep, r); err != nil {
		return err
	}
	return rep.failed()
}

// drainingPredecessor reports whether addr is held by a coen daemon of the same
// role that is draining. A live (not draining) instance on the port is a real
// conflict, like any other process.
func drainingPredecessor(ctx context.Context, addr, role string) bool {
	h, ok := metrics.Probe(ctx, addr)
	return ok && h.Role == role && h.Draining
}

// metricsBinding is how serveDaemon gets its metrics listener: an already
// bound ln, or retryAddr to keep binding while a draining predecessor of the
// same role still holds it. Both empty means metrics are off.
type metricsBinding struct {
	ln        net.Listener
	retryAddr string
}

// metricsRetryInterval is how often a busy metrics port is retried.
var metricsRetryInterval = time.Second

// await returns the listener, retrying retryAddr until it binds or ctx ends. It
// stops waiting once the port is held by anything other than a draining coen
// daemon of the same role (the predecessor finished and something else took
// the port, or the holder is not draining after all). Giving up is logged as
// an error: the daemon keeps serving traffic but has no metrics endpoint.
func (m metricsBinding) await(ctx context.Context, log *slog.Logger, role string) (net.Listener, bool) {
	if m.ln != nil {
		return m.ln, true
	}
	t := time.NewTicker(metricsRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-t.C:
		}
		ln, err := net.Listen("tcp", m.retryAddr)
		if err == nil {
			return ln, true
		}
		if netx.IsAddrInUse(err) && drainingPredecessor(ctx, m.retryAddr, role) {
			continue
		}
		// The probe can miss a predecessor that is just shutting its metrics
		// server down; the port may have been freed meanwhile, so try once
		// more before giving up.
		if ln, err2 := net.Listen("tcp", m.retryAddr); err2 == nil {
			return ln, true
		}
		if ctx.Err() != nil {
			return nil, false // shutting down; the probe was cut short
		}
		log.Error("metrics.listen_failed", "address", m.retryAddr, "error", err.Error(), "impact", "running without a metrics endpoint until restart")
		return nil, false
	}
}

// serveDaemon is runDaemon with the shutdown signal supplied as ctx. r.Run gets
// ctx, so cancelling it starts the graceful drain. The admin socket and the
// metrics endpoint deliberately outlive ctx: they stay up until r.Run returns,
// so `coen status` and Prometheus can watch in-flight streams drain to zero.
//
// hup delivers SIGHUP: with rep set it replaces the agent process (see
// replace.go), otherwise it reloads the log level.
func serveDaemon(ctx context.Context, log *slog.Logger, lv *slog.LevelVar, state *obs.State, socket string, m metricsBinding, hup chan os.Signal, reloadLevel func() (string, error), rep *replacer, r runner) error {
	lifetime, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	// Defers run last-in first-out: stop the side servers once r.Run has
	// returned, then wait for them to shut down before returning.
	defer wg.Wait()
	defer stop()

	if m.ln != nil || m.retryAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ln, ok := m.await(lifetime, log, state.Role())
			if !ok {
				return
			}
			if err := metrics.Serve(lifetime, ln, metrics.Handler(state, Version), log); err != nil {
				log.Warn("metrics.error", "error", err.Error())
			}
		}()
	}

	if socket != "" {
		srv := &admin.Server{
			Log:      log,
			Snapshot: state.Snapshot,
			SetLevel: func(l slog.Level) error { lv.Set(l); return nil },
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(lifetime, socket); err != nil {
				log.Warn("admin.error", "error", err.Error())
			}
		}()
	}

	go func() {
		for {
			select {
			case <-lifetime.Done():
				return
			case <-hup:
				if rep != nil {
					go func() {
						if err := rep.replace(); err != nil {
							log.Warn("reload.failed", "error", err.Error(), "impact", "this agent keeps running")
						}
					}()
					continue
				}
				level, err := reloadLevel()
				if err != nil {
					log.Warn("config.reload_error", "error", err.Error())
					continue
				}
				l, err := obs.ParseLevel(level)
				if err != nil {
					log.Warn("config.reload_error", "error", err.Error())
					continue
				}
				lv.Set(l)
				log.Info("config.reloaded", "level", level)
			}
		}
	}()

	notifyReady(log)
	return r.Run(ctx)
}
