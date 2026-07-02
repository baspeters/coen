package cli

import (
	"encoding/json"
	"fmt"

	"github.com/baspeters/coen/internal/admin"
	"github.com/spf13/cobra"
)

func init() { register(newStatusCmd()) }

func newStatusCmd() *cobra.Command {
	var socket string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show live status from a running coen daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snap, err := admin.Status(socket)
			if err != nil {
				return fmt.Errorf("connect to admin socket %s: %w", socket, err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				b, _ := json.MarshalIndent(snap, "", "  ")
				fmt.Fprintln(out, string(b))
				return nil
			}
			fmt.Fprintf(out, "tunnel:     %v\n", snap.TunnelConnected)
			if snap.TunnelConnected {
				fmt.Fprintf(out, "since:      %s\n", snap.ConnectedSince.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(out, "peer_fp:    %s\n", snap.PeerFingerprint)
			}
			fmt.Fprintf(out, "streams:    %d active / %d total\n", snap.ActiveStreams, snap.TotalStreams)
			fmt.Fprintf(out, "bytes:      %d in / %d out\n", snap.BytesIn, snap.BytesOut)
			fmt.Fprintf(out, "handshakes: %d ok / %d fail\n", snap.HandshakeOK, snap.HandshakeFail)
			fmt.Fprintf(out, "reconnects: %d\n", snap.Reconnects)
			if snap.LastError != "" {
				fmt.Fprintf(out, "last_error: %s\n", snap.LastError)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "/run/coen/edge.sock", "admin socket path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}
