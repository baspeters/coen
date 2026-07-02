package cli

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed assets/*.service assets/*.yaml
var assets embed.FS

func init() { register(newInstallCmd) }

func newInstallCmd() *cobra.Command {
	var unitDir, configDir, bin string
	cmd := &cobra.Command{
		Use:   "install [edge|agent]",
		Short: "Install a systemd unit and example config for a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			if role != "edge" && role != "agent" {
				return fmt.Errorf("role must be 'edge' or 'agent'")
			}
			configPath := filepath.Join(configDir, role+".yaml")

			tmplBytes, err := assets.ReadFile("assets/coen-" + role + ".service")
			if err != nil {
				return err
			}
			tmpl, err := template.New("unit").Parse(string(tmplBytes))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(unitDir, 0o755); err != nil {
				return err
			}
			unitPath := filepath.Join(unitDir, "coen-"+role+".service")
			f, err := os.Create(unitPath)
			if err != nil {
				return err
			}
			if err := tmpl.Execute(f, map[string]string{"Bin": bin, "Config": configPath}); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}

			if err := os.MkdirAll(configDir, 0o750); err != nil {
				return err
			}
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				example, err := assets.ReadFile("assets/" + role + ".yaml")
				if err != nil {
					return err
				}
				if err := os.WriteFile(configPath, example, 0o640); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed %s\nexample config: %s\nnext: edit the config, then run:\n  sudo systemctl enable --now coen-%s\n", unitPath, configPath, role)
			return nil
		},
	}
	cmd.Flags().StringVar(&unitDir, "unit-dir", "/etc/systemd/system", "systemd unit directory")
	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/coen", "config directory")
	cmd.Flags().StringVar(&bin, "bin", "/usr/local/bin/coen", "path to the coen binary")
	return cmd
}
