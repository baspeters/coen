package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
)

func newVersionTestAgent(t *testing.T, agentVersion string, buf *bytes.Buffer) *Agent {
	t.Helper()
	return &Agent{
		version: agentVersion,
		log:     slog.New(slog.NewTextHandler(buf, nil)),
		state:   &obs.State{},
		routes:  route.Build([]route.Entry[string]{{Pattern: "*", Value: "127.0.0.1:1"}}),
	}
}

// driveStream writes a preamble carrying edgeVersion and drains the agent's
// reply; the backend (127.0.0.1:1) is unreachable so handleStream returns after
// a 502, but the version check has already run by then.
func driveStream(t *testing.T, a *Agent, edgeVersion string) {
	t.Helper()
	client, stream := net.Pipe()
	go func() {
		_ = tunnel.WritePreamble(client, tunnel.Preamble{ConnID: "c1", Host: "x", EdgeVersion: edgeVersion})
		_, _ = io.Copy(io.Discard, client)
	}()
	a.handleStream(context.Background(), stream)
}

func TestHandleStreamWarnsOnVersionMismatch(t *testing.T) {
	var buf bytes.Buffer
	a := newVersionTestAgent(t, "agent-v", &buf)
	driveStream(t, a, "edge-v")
	if !strings.Contains(buf.String(), "version.mismatch") {
		t.Fatalf("expected a version.mismatch warning, got: %s", buf.String())
	}
}

func TestHandleStreamNoWarnWhenVersionsMatch(t *testing.T) {
	var buf bytes.Buffer
	a := newVersionTestAgent(t, "same", &buf)
	driveStream(t, a, "same")
	if strings.Contains(buf.String(), "version.mismatch") {
		t.Fatalf("did not expect a version warning when versions match: %s", buf.String())
	}
}
