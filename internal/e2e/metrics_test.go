package e2e

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/metrics"
	"github.com/baspeters/coen/internal/obs"
)

func scrape(t *testing.T, s *obs.State) string {
	t.Helper()
	return string(metrics.Encode(metrics.Collect(s.Detail(), "test")))
}

func request(t *testing.T, addr, host string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: "+host+"\r\n\r\n")
	b, _ := io.ReadAll(c)
	return string(b)
}

// waitFor polls the rendered metrics of s until every line is present.
func waitFor(t *testing.T, s *obs.State, lines ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		out := scrape(t, s)
		missing := ""
		for _, l := range lines {
			if !strings.Contains(out, l+"\n") {
				missing = l
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metric line %q never appeared in:\n%s", missing, out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A real edge and agent count per-route traffic and failures on both sides.
func TestEndToEndMetrics(t *testing.T) {
	backend := startBackend(t)
	addr, _, _, edgeState, agentState := buildStackStates(t, "info", nil,
		[]string{"app.example.com", "*.example.com"},
		// The agent deliberately has no route for the wildcard, so a request to
		// other.example.com reaches the agent and fails there with no_route.
		[]config.AgentRoute{{Host: "app.example.com", Service: backend.Addr().String()}})

	if resp := request(t, addr, "app.example.com"); !strings.Contains(resp, "hello from backend") {
		t.Fatalf("app request failed: %q", resp)
	}
	if resp := request(t, addr, "nope.invalid"); !strings.Contains(resp, "404") {
		t.Fatalf("unrouted request should 404, got %q", resp)
	}
	if resp := request(t, addr, "other.example.com"); !strings.Contains(resp, "502") {
		t.Fatalf("agent without a route should 502, got %q", resp)
	}

	waitFor(t, edgeState,
		`coen_streams_total{route="app.example.com"} 1`,
		`coen_streams_active{route="app.example.com"} 0`,
		`coen_streams_total{route="*.example.com"} 1`,
		`coen_ingress_rejected_total{reason="no_route"} 1`,
		`coen_tunnel_handshakes_total{result="ok"} 1`,
	)
	waitFor(t, agentState,
		`coen_tunnel_up 1`,
		`coen_streams_total{route="app.example.com"} 1`,
		`coen_stream_errors_total{reason="no_route"} 1`,
		`coen_stream_errors_total{reason="dial_error",route="app.example.com"} 0`,
	)

	agents := edgeState.Snapshot().Agents
	if len(agents) != 1 {
		t.Fatalf("want one connected agent, got %+v", agents)
	}
	waitFor(t, edgeState, `coen_agent_connected{fingerprint="`+agents[0].Fingerprint+`"} 1`)
	// Bytes in both directions are recorded for the served route on both ends.
	for _, s := range []*obs.State{edgeState, agentState} {
		out := scrape(t, s)
		for _, dir := range []string{"in", "out"} {
			if strings.Contains(out, `coen_stream_bytes_total{direction="`+dir+`",route="app.example.com"} 0`+"\n") {
				t.Fatalf("expected non-zero %s bytes for the served route:\n%s", dir, out)
			}
		}
	}
}

// Bytes of a long-lived stream are visible while it is still open, not only
// when it closes.
func TestEndToEndLiveStreamBytes(t *testing.T) {
	backend := startBackend(t)
	addr, _, _, edgeState, agentState := buildStackStates(t, "info", nil,
		[]string{"*"}, []config.AgentRoute{{Host: "*", Service: backend.Addr().String()}})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload := strings.Repeat("z", 50000)
	_, _ = io.WriteString(conn, payload)
	if _, err := io.ReadFull(br, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	// The WebSocket is still open: active is 1 and the echoed bytes count.
	for _, s := range []*obs.State{edgeState, agentState} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			r := s.Detail().Routes[0]
			if r.Active == 1 && r.BytesIn >= int64(len(payload)) && r.BytesOut >= int64(len(payload)) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: open stream bytes not visible: %+v", s.Detail().Role, r)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
