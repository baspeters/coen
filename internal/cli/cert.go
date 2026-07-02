package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/baspeters/coen/internal/pki"
	"github.com/spf13/cobra"
)

func init() { register(newCertCmd) }

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Manage the Coen tunnel PKI"}
	cmd.AddCommand(newCertInitCmd(), newCertEdgeCmd(), newCertAgentCmd())
	return cmd
}

func loadCADir(dir string) (*pki.CA, error) {
	caCert, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read ca.crt: %w", err)
	}
	caKey, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("read ca.key: %w", err)
	}
	return pki.LoadCA(caCert, caKey)
}

func newCertInitCmd() *cobra.Command {
	var dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new Coen CA (ca.crt, ca.key)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caCertPath := filepath.Join(dir, "ca.crt")
			if _, err := os.Stat(caCertPath); err == nil && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", caCertPath)
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			ca, err := pki.CreateCA()
			if err != nil {
				return err
			}
			if err := pki.WritePEM(caCertPath, ca.CertPEM()); err != nil {
				return err
			}
			if err := pki.WritePEM(filepath.Join(dir, "ca.key"), ca.KeyPEM()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created CA in %s\nfingerprint: %s\n", dir, pki.Fingerprint(ca.Cert))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/etc/coen/pki", "PKI directory")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing CA")
	return cmd
}

func newCertEdgeCmd() *cobra.Command {
	var dir, host string
	cmd := &cobra.Command{
		Use:   "edge",
		Short: "Issue the edge (server) certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if host == "" {
				return fmt.Errorf("--host is required")
			}
			ca, err := loadCADir(dir)
			if err != nil {
				return err
			}
			certPEM, keyPEM, err := ca.IssueServer(host)
			if err != nil {
				return err
			}
			return writeLeaf(cmd, dir, "edge", certPEM, keyPEM)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/etc/coen/pki", "PKI directory")
	cmd.Flags().StringVar(&host, "host", "", "edge hostname or IP (certificate subject + SAN)")
	return cmd
}

func newCertAgentCmd() *cobra.Command {
	var dir, name string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Issue an agent (client) certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			ca, err := loadCADir(dir)
			if err != nil {
				return err
			}
			certPEM, keyPEM, err := ca.IssueClient(name)
			if err != nil {
				return err
			}
			return writeLeaf(cmd, dir, "agent", certPEM, keyPEM)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/etc/coen/pki", "PKI directory")
	cmd.Flags().StringVar(&name, "name", "", "agent identity (certificate CN)")
	return cmd
}

func writeLeaf(cmd *cobra.Command, dir, role string, certPEM, keyPEM []byte) error {
	certPath := filepath.Join(dir, role+".crt")
	keyPath := filepath.Join(dir, role+".key")
	if err := pki.WritePEM(certPath, certPEM); err != nil {
		return err
	}
	if err := pki.WritePEM(keyPath, keyPEM); err != nil {
		return err
	}
	fp, err := pki.FingerprintPEM(certPEM)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s\nfingerprint: %s\n", certPath, keyPath, fp)
	return nil
}
