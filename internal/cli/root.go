package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// builders holds subcommand constructors; each command file registers one from
// its init(). newRootCmd invokes them to build FRESH command instances on every
// call, so cobra flag state never leaks between Execute (or test) invocations.
var builders []func() *cobra.Command

// register adds a subcommand constructor; each command file calls this from its init().
func register(build func() *cobra.Command) { builders = append(builders, build) }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "coen",
		Short:         "A lightweight, secure, self-hosted tunnel",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	for _, build := range builders {
		root.AddCommand(build())
	}
	return root
}

// Execute runs the coen CLI and exits non-zero on error.
func Execute() {
	os.Exit(run(newRootCmd(), os.Stderr))
}

// run executes root, printing any error to errw, and returns the process exit
// code. Kept separate from Execute (which calls os.Exit) so it is testable.
func run(root *cobra.Command, errw io.Writer) int {
	if err := root.Execute(); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}
