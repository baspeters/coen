package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/spf13/cobra"
)

func init() { register(newStatusCmd) }

func newStatusCmd() *cobra.Command {
	var socket, role, cfgPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show live status from a running coen daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if socket == "" {
				s, err := resolveStatusSocket(role, cfgPath)
				if err != nil {
					return err
				}
				socket = s
			}
			snap, err := admin.Status(socket)
			if err != nil {
				return fmt.Errorf("connect to admin socket %s: %w", socket, err)
			}
			renderStatus(cmd.OutOrStdout(), snap, asJSON)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "admin socket path (overrides auto-detection)")
	cmd.Flags().StringVar(&role, "role", "", "edge | agent (default: auto-detected from the running daemon)")
	cmd.Flags().StringVar(&cfgPath, "config", "", "config to read the admin socket from (default: the running daemon's)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

// resolveStatusSocket determines which admin socket to connect to: the role
// comes from --role or from the running daemon (detectRole), and the socket
// path from that role's config's admin.socket.
func resolveStatusSocket(role, cfgPath string) (string, error) {
	if role == "" {
		r, c, err := detectRole()
		if err != nil {
			if errors.Is(err, errNoDaemon) {
				return "", fmt.Errorf("no running coen daemon found; start one, or pass --socket/--role")
			}
			return "", err
		}
		role = r
		if cfgPath == "" {
			cfgPath = c
		}
	}
	if cfgPath == "" {
		cfgPath = filepath.Join("/etc/coen", role+".yaml")
	}
	return adminSocketFromConfig(role, cfgPath)
}

func adminSocketFromConfig(role, path string) (string, error) {
	var socket string
	// Only admin.socket is needed to reach a running daemon, so the file is
	// decoded (strictly) without validating the rest.
	var err error
	switch role {
	case "edge":
		socket, err = config.EdgeAdminSocket(path)
	case "agent":
		socket, err = config.AgentAdminSocket(path)
	default:
		return "", fmt.Errorf("role must be 'edge' or 'agent', got %q", role)
	}
	if err != nil {
		return "", fmt.Errorf("load %s: %w", path, err)
	}
	if socket == "" {
		return "", fmt.Errorf("%s has no admin.socket configured; pass --socket", path)
	}
	return socket, nil
}

func renderStatus(out io.Writer, snap obs.Snapshot, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Fprintln(out, string(b))
		return
	}
	if snap.Role != "" {
		fmt.Fprintf(out, "role:       %s\n", snap.Role)
	}
	switch snap.Role {
	case "edge":
		renderEdgeStatus(out, snap)
	case "agent":
		renderAgentStatus(out, snap)
	default:
		// Unknown role (e.g. an older daemon that doesn't tag its snapshot).
		renderAgentStatus(out, snap)
		renderEdgeStatus(out, snap)
	}
	if snap.LastError != "" {
		fmt.Fprintf(out, "last_error: %s\n", snap.LastError)
	}
}

// agentIP returns the connecting IP from a remote address, dropping the
// ephemeral source port. Falls back to the raw value (or "unknown") if it is
// not a host:port pair.
func agentIP(remoteAddr string) string {
	if remoteAddr == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func renderEdgeStatus(out io.Writer, s obs.Snapshot) {
	if s.SelfFingerprint != "" {
		fmt.Fprintf(out, "self_fp:    %s\n", s.SelfFingerprint)
	}
	// One agent can have several sessions (a shared certificate, or a
	// restarting agent whose old session is still draining).
	draining := 0
	fps := map[string]bool{}
	for _, a := range s.Agents {
		fps[a.Fingerprint] = true
		if a.Draining {
			draining++
		}
	}
	// Agents sharing a certificate cannot be told apart, so with several
	// sessions per certificate both counts are shown.
	switch {
	case len(s.Agents) == len(fps) && draining == 0:
		fmt.Fprintf(out, "agents:     %d connected\n", len(fps))
	case draining == 0:
		fmt.Fprintf(out, "agents:     %s, %s\n", plural(len(s.Agents), "session"), plural(len(fps), "certificate"))
	default:
		fmt.Fprintf(out, "agents:     %s (%d draining), %s\n", plural(len(s.Agents), "session"), draining, plural(len(fps), "certificate"))
	}
	for _, a := range s.Agents {
		suffix := ""
		if a.Draining {
			suffix = ", draining"
		}
		fmt.Fprintf(out, "  - %s (%s, %s%s)\n", agentIP(a.RemoteAddr), a.ConnectedSince.Format("2006-01-02 15:04:05"), a.Fingerprint, suffix)
	}
	fmt.Fprintf(out, "streams:    %d active / %d max\n", s.ActiveStreams, s.MaxStreams)
	fmt.Fprintf(out, "bytes:      %d in / %d out\n", s.BytesIn, s.BytesOut)
	// "rejected" is unauthenticated/incompatible peers refused at the TLS
	// handshake (routine scanner noise on a public mTLS port); "fail" is a peer
	// that authenticated but was not authorized for any route, or a real
	// agent that failed the readiness ping.
	if s.HandshakeDup > 0 || s.HandshakeCapped > 0 {
		fmt.Fprintf(out, "handshakes: %d ok / %d fail / %d rejected / %d duplicate / %d capped\n", s.HandshakeOK, s.HandshakeFail, s.HandshakeRejected, s.HandshakeDup, s.HandshakeCapped)
	} else {
		fmt.Fprintf(out, "handshakes: %d ok / %d fail / %d rejected\n", s.HandshakeOK, s.HandshakeFail, s.HandshakeRejected)
	}
}

func renderAgentStatus(out io.Writer, s obs.Snapshot) {
	if s.SelfFingerprint != "" {
		fmt.Fprintf(out, "self_fp:    %s\n", s.SelfFingerprint)
	}
	if s.TunnelConnected {
		fmt.Fprintf(out, "tunnel:     connected\n")
		fmt.Fprintf(out, "since:      %s\n", s.ConnectedSince.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(out, "peer_fp:    %s\n", s.PeerFingerprint)
	} else {
		fmt.Fprintf(out, "tunnel:     disconnected\n")
	}
	fmt.Fprintf(out, "reconnects: %d\n", s.Reconnects)
	fmt.Fprintf(out, "streams:    %d active / %d max\n", s.ActiveStreams, s.MaxStreams)
	fmt.Fprintf(out, "bytes:      %d in / %d out\n", s.BytesIn, s.BytesOut)
	fmt.Fprintf(out, "handshakes: %d ok / %d fail\n", s.HandshakeOK, s.HandshakeFail)
}

// plural returns n and word, with an s unless n is 1.
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
