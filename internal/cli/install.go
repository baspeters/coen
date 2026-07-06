package cli

import (
	"embed"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed assets/*.service assets/*.yaml assets/*.plist
var assets embed.FS

// Seams for testing; overridden in tests to exercise every OS and user state.
var (
	osGOOS      = runtime.GOOS
	lookupUser  = user.Lookup
	lookupGroup = user.LookupGroup
)

func init() { register(newInstallCmd) }

func newInstallCmd() *cobra.Command {
	var unitDir, configDir, bin string
	cmd := &cobra.Command{
		Use:   "install [edge|agent]",
		Short: "Install a service definition and example config for a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			if role != "edge" && role != "agent" {
				return fmt.Errorf("role must be 'edge' or 'agent'")
			}
			configPath := filepath.Join(configDir, role+".yaml")
			if unitDir == "" {
				unitDir = defaultUnitDir(osGOOS)
			}

			filename, content, err := renderService(osGOOS, role, bin, configPath)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(unitDir, 0o755); err != nil {
				return err
			}
			unitPath := filepath.Join(unitDir, filename)
			if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
				return err
			}

			if err := os.MkdirAll(configDir, 0o750); err != nil {
				return err
			}
			// Create the drop-in route directory (edge.d / agent.d) so operators
			// can add route fragments without editing the base config.
			if err := os.MkdirAll(filepath.Join(configDir, role+".d"), 0o750); err != nil {
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

			if osGOOS == "linux" {
				checkServiceUser(cmd)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "installed %s\nexample config: %s\nnext: edit the config, then run:\n  %s\n", unitPath, configPath, startCommand(osGOOS, role, unitPath))
			return nil
		},
	}
	cmd.Flags().StringVar(&unitDir, "unit-dir", "", "service definition directory (default: /etc/systemd/system on Linux, /Library/LaunchDaemons on macOS)")
	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/coen", "config directory")
	cmd.Flags().StringVar(&bin, "bin", "/usr/local/bin/coen", "path to the coen binary")
	return cmd
}

// checkServiceUser advises (non-fatally) when the systemd unit's User=coen is
// not present. It is Linux-only; the launchd path runs as root.
func checkServiceUser(cmd *cobra.Command) {
	_, uerr := lookupUser("coen")
	_, gerr := lookupGroup("coen")
	if uerr == nil && gerr == nil {
		return
	}
	fmt.Fprint(cmd.ErrOrStderr(),
		"warning: the unit runs as user 'coen', which was not found. Create it with:\n"+
			"  sudo groupadd --system coen\n"+
			"  sudo useradd  --system --gid coen --no-create-home --shell /usr/sbin/nologin coen\n"+
			"(the .deb/.rpm/.apk packages create this user automatically.)\n")
}

func defaultUnitDir(goos string) string {
	if goos == "darwin" {
		return "/Library/LaunchDaemons"
	}
	return "/etc/systemd/system"
}

func renderTemplate(tmplBytes []byte, data map[string]string) (string, error) {
	tmpl, err := template.New("svc").Parse(string(tmplBytes))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// renderService produces the service-definition filename and content for the
// target OS. It returns an error on an OS coen install does not support.
func renderService(goos, role, bin, configPath string) (string, string, error) {
	switch goos {
	case "linux":
		tmplBytes, err := assets.ReadFile("assets/coen-" + role + ".service")
		if err != nil {
			return "", "", err
		}
		content, err := renderTemplate(tmplBytes, map[string]string{"Bin": bin, "Config": configPath})
		if err != nil {
			return "", "", err
		}
		return "coen-" + role + ".service", content, nil
	case "darwin":
		tmplBytes, err := assets.ReadFile("assets/coen.plist")
		if err != nil {
			return "", "", err
		}
		label := "com.coen." + role
		content, err := renderTemplate(tmplBytes, map[string]string{
			"Label": label, "Bin": bin, "Role": role,
			"Config": configPath, "LogPath": "/var/log/coen-" + role + ".log",
		})
		if err != nil {
			return "", "", err
		}
		return label + ".plist", content, nil
	default:
		return "", "", fmt.Errorf("coen install is not available on %s; run 'coen %s --config %s' under your platform's service manager (rc.d, OpenRC)", goos, role, configPath)
	}
}

func startCommand(goos, role, unitPath string) string {
	if goos == "darwin" {
		return "sudo launchctl bootstrap system " + unitPath
	}
	return "sudo systemctl enable --now coen-" + role
}
