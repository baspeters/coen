package edge

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/route"
)

// A dead tunnel session (silent partition) must be evicted the moment an ingress
// request fails to open a stream on it, so a reconnecting agent can register
// immediately instead of being refused while every request 502s.
func TestHandleIngressEvictsDeadSessionOnOpenStreamFailure(t *testing.T) {
	srv, cli := newServerSession(t)
	e := &Edge{
		cfg:   &config.EdgeConfig{},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		state: &obs.State{},
		reg:   newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{
			{Pattern: "app.example.com", Value: &routeState{fingerprint: "FP-A"}},
		}),
	}
	if !e.reg.register("FP-A", srv) {
		t.Fatal("register should succeed on an empty registry")
	}
	e.state.AgentConnected("FP-A")

	// Kill the session so OpenStream fails, as on a silent partition.
	_ = cli.Close()
	_ = srv.Close()

	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"))
	}()
	resp := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(resp)
	if !strings.Contains(string(resp[:n]), "502") {
		t.Fatalf("expected 502, got %q", resp[:n])
	}
	_ = client.Close()

	if _, ok := e.reg.get("FP-A"); ok {
		t.Fatal("dead session was not evicted from the registry")
	}
}
