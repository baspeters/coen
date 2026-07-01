package cli

import (
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var subcommands []*cobra.Command

// register adds a subcommand; each command file calls this from its init().
func register(c *cobra.Command) { subcommands = append(subcommands, c) }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "coen",
		Short:         "Coen — a lightweight, secure self-hosted tunnel",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(subcommands...)
	return root
}

// Execute runs the coen CLI.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
