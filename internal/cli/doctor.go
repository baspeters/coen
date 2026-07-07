package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/doctor"
	"github.com/spf13/cobra"
)

func init() { register(newDoctorCmd) }

func newDoctorCmd() *cobra.Command {
	var cfgPath, role string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the local edge/agent setup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if role == "" {
				r, c, err := detectRole()
				if err != nil {
					if errors.Is(err, errNoDaemon) {
						return fmt.Errorf("no running coen daemon to auto-detect; pass --role edge|agent (with --config for a preflight check)")
					}
					return err
				}
				role = r
				if cfgPath == "" {
					cfgPath = c
				}
			}
			if cfgPath == "" && (role == "edge" || role == "agent") {
				cfgPath = "/etc/coen/" + role + ".yaml"
			}
			var results []doctor.Result
			switch role {
			case "edge":
				cfg, err := config.LoadEdge(cfgPath)
				if err != nil {
					return err
				}
				results = doctor.CheckEdge(cfg)
			case "agent":
				cfg, err := config.LoadAgent(cfgPath)
				if err != nil {
					return err
				}
				results = doctor.CheckAgent(cfg)
			default:
				return fmt.Errorf("--role must be 'edge' or 'agent'")
			}

			out := cmd.OutOrStdout()
			if asJSON {
				b, _ := json.MarshalIndent(results, "", "  ")
				fmt.Fprintln(out, string(b))
			} else {
				color := colorEnabled(out)
				fmt.Fprintf(out, "coen doctor: %s checks (config: %s)\n\n", role, cfgPath)
				for _, r := range results {
					mark := paint("✓", ansiGreen, color)
					if !r.OK {
						mark = paint("✗", ansiRed, color)
					}
					fmt.Fprintf(out, "%s %s - %s\n", mark, r.Name, r.Detail)
					if !r.OK && r.Hint != "" {
						fmt.Fprintf(out, "    hint: %s\n", r.Hint)
					}
				}
			}
			if n := countFailures(results); n > 0 {
				return fmt.Errorf("doctor found %d problem(s)", n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "config file (defaults to /etc/coen/<role>.yaml)")
	cmd.Flags().StringVar(&role, "role", "", "edge | agent")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

func countFailures(rs []doctor.Result) int {
	n := 0
	for _, r := range rs {
		if !r.OK {
			n++
		}
	}
	return n
}
