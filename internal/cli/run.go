package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/obs"
	"github.com/spf13/cobra"
)

func init() {
	register(newEdgeCmd())
	register(newAgentCmd())
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
			log, lv, err := obs.NewLogger(cfg.Log.Level, cfg.Log.Format, os.Stderr)
			if err != nil {
				return err
			}
			state := &obs.State{}
			e, err := edge.New(cfg, log, state)
			if err != nil {
				return err
			}
			return runDaemon(log, lv, state, cfg.Admin.Socket, func() (string, error) { return edgeLevel(cfgPath) }, e)
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
			log, lv, err := obs.NewLogger(cfg.Log.Level, cfg.Log.Format, os.Stderr)
			if err != nil {
				return err
			}
			state := &obs.State{}
			a, err := agent.New(cfg, log, state)
			if err != nil {
				return err
			}
			return runDaemon(log, lv, state, cfg.Admin.Socket, func() (string, error) { return agentLevel(cfgPath) }, a)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/coen/agent.yaml", "config file")
	return cmd
}

func edgeLevel(path string) (string, error) {
	c, err := config.LoadEdge(path)
	if err != nil {
		return "", err
	}
	return c.Log.Level, nil
}

func agentLevel(path string) (string, error) {
	c, err := config.LoadAgent(path)
	if err != nil {
		return "", err
	}
	return c.Log.Level, nil
}

func runDaemon(log *slog.Logger, lv *slog.LevelVar, state *obs.State, socket string, reloadLevel func() (string, error), r runner) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if socket != "" {
		srv := &admin.Server{
			Snapshot: state.Snapshot,
			SetLevel: func(l slog.Level) error { lv.Set(l); return nil },
		}
		go func() {
			if err := srv.Serve(ctx, socket); err != nil {
				log.Warn("admin.error", "error", err.Error())
			}
		}()
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
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

	return r.Run(ctx)
}
