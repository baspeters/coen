package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() { register(newVersionCmd) }

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Coen version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "coen %s\n", Version)
			return nil
		},
	}
}
