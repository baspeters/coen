package metrics

import (
	"strings"
	"testing"

	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/obs/obstest"
)

func render(t *testing.T, s *obs.State) string {
	t.Helper()
	return string(Encode(Collect(s.Detail(), "v1.2.3")))
}

func mustContain(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l+"\n") {
			t.Errorf("missing line %q in:\n%s", l, out)
		}
	}
}

func TestCollectEdge(t *testing.T) {
	s := obs.NewState("edge")
	app := s.Route("app.example.com")
	s.Route("*.example.com")
	s.ExpectAgents(map[string]bool{"SHA256:aaa": true, "SHA256:bbb": true})
	agentA := obstest.ConnectAgent(s, "SHA256:aaa", "203.0.113.1:5000")
	obstest.ConnectAgent(s, "SHA256:aaa", "203.0.113.9:5000")               // a second session (shared cert)
	obstest.ConnectAgent(s, "SHA256:bbb", "203.0.113.7:5000").SetDraining() // draining: not serving
	agentA.Reserve()
	agentA.Commit()
	s.HandshakeOK()
	s.HandshakeRejected()
	s.HandshakeDuplicate()
	s.StreamOpened(app)
	s.StreamOpened(app)
	app.Bytes().AddIn(100)
	app.Bytes().AddOut(2000)
	s.StreamClosed(app)
	app.Failure(obs.ReasonNoAgent)
	s.Failure(obs.ReasonNoRoute)
	s.Failure(obs.ReasonNoRoute)
	s.HeaderTimeout()

	out := render(t, s)
	mustContain(t, out,
		`coen_build_info{role="edge",version="v1.2.3"} 1`,
		`coen_streams_active{route="app.example.com"} 1`,
		`coen_streams_active{route="*.example.com"} 0`,
		`coen_streams_total{route="app.example.com"} 2`,
		`coen_stream_bytes_total{direction="in",route="app.example.com"} 100`,
		`coen_stream_bytes_total{direction="out",route="app.example.com"} 2000`,
		`coen_streams_peak 2`,
		`coen_tunnel_handshakes_total{result="ok"} 1`,
		`coen_tunnel_handshakes_total{result="fail"} 0`,
		`coen_tunnel_handshakes_total{result="rejected"} 1`,
		`coen_tunnel_handshakes_total{result="duplicate"} 1`,
		`coen_tunnel_handshakes_total{result="capped"} 0`,
		`coen_agent_connected{fingerprint="SHA256:aaa"} 1`,
		`coen_agent_connected{fingerprint="SHA256:bbb"} 1`, // draining still counts as connected
		`coen_agent_sessions{fingerprint="SHA256:aaa"} 2`,
		`coen_agent_sessions{fingerprint="SHA256:bbb"} 0`,
		`coen_agent_streams_active{fingerprint="SHA256:aaa"} 1`,
		`coen_agent_streams_total{fingerprint="SHA256:aaa"} 1`,
		`coen_agent_streams_total{fingerprint="SHA256:bbb"} 0`,
		`coen_ingress_rejected_total{reason="no_route"} 2`,
		`coen_ingress_header_timeouts_total 1`,
		`coen_ingress_rejected_total{reason="bad_request"} 0`,
		`coen_ingress_rejected_total{reason="max_connections"} 0`,
		`coen_ingress_rejected_total{reason="no_agent",route="app.example.com"} 1`,
		`coen_ingress_rejected_total{reason="stream_error",route="app.example.com"} 0`,
		`coen_ingress_rejected_total{reason="route_max_connections",route="*.example.com"} 0`,
	)
	if !strings.Contains(out, "coen_process_start_time_seconds ") {
		t.Error("missing coen_process_start_time_seconds")
	}
	for _, agentOnly := range []string{"coen_tunnel_up", "coen_tunnel_reconnects_total", "coen_stream_errors_total"} {
		if strings.Contains(out, agentOnly) {
			t.Errorf("edge output should not contain agent metric %s", agentOnly)
		}
	}
}

func TestCollectAgent(t *testing.T) {
	s := obs.NewState("agent")
	r := s.Route("*")
	s.SetConnected("SHA256:edge")
	s.Reconnect()
	s.HandshakeOK()
	s.HandshakeFail()
	r.Failure(obs.ReasonDialError)
	s.Failure(obs.ReasonPreambleError)

	out := render(t, s)
	mustContain(t, out,
		`coen_build_info{role="agent",version="v1.2.3"} 1`,
		`coen_tunnel_up 1`,
		`coen_tunnel_reconnects_total 1`,
		`coen_tunnel_handshakes_total{result="ok"} 1`,
		`coen_tunnel_handshakes_total{result="fail"} 1`,
		`coen_stream_errors_total{reason="dial_error",route="*"} 1`,
		`coen_stream_errors_total{reason="preamble_error"} 1`,
		`coen_stream_errors_total{reason="no_route"} 0`,
	)
	for _, edgeOnly := range []string{"coen_agent_connected", "coen_ingress_rejected_total", "coen_ingress_header_timeouts_total", `result="rejected"`, `result="duplicate"`} {
		if strings.Contains(out, edgeOnly) {
			t.Errorf("agent output should not contain edge metric %s", edgeOnly)
		}
	}

	s.SetDisconnected()
	mustContain(t, render(t, s), `coen_tunnel_up 0`)
}

// Every family must be declared exactly once and every sample line must belong
// to the family declared above it, which is what Prometheus parsers require.
func TestCollectIsWellFormed(t *testing.T) {
	for _, role := range []string{"edge", "agent", ""} {
		s := obs.NewState(role)
		s.Route("a")
		s.Route("b").Failure(obs.ReasonDialError)
		out := render(t, s)
		seen := map[string]bool{}
		current := ""
		for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			switch {
			case strings.HasPrefix(ln, "# HELP "):
				continue
			case strings.HasPrefix(ln, "# TYPE "):
				name := strings.Fields(ln)[2]
				if seen[name] {
					t.Fatalf("role %q: family %s declared twice", role, name)
				}
				seen[name] = true
				current = name
			default:
				name := ln
				if i := strings.IndexAny(ln, "{ "); i >= 0 {
					name = ln[:i]
				}
				if name != current {
					t.Fatalf("role %q: sample %q is outside its family %q", role, ln, current)
				}
			}
		}
	}
}

func TestCollectZeroStateOmitsStartTime(t *testing.T) {
	var s obs.State
	if out := render(t, &s); strings.Contains(out, "coen_process_start_time_seconds") {
		t.Fatalf("a zero State has no start time and should not report one:\n%s", out)
	}
}

// A reason a role is not listed as recording is still exported once non-zero.
func TestCollectExportsUnlistedNonZeroReason(t *testing.T) {
	s := obs.NewState("agent")
	s.Route("*").Failure(obs.ReasonNoAgent) // an edge reason, recorded on an agent route
	out := render(t, s)
	mustContain(t, out, `coen_stream_errors_total{reason="no_agent",route="*"} 1`)
	if strings.Contains(out, `coen_stream_errors_total{reason="stream_error"`) {
		t.Fatal("zero, unlisted reasons must not be exported")
	}
}

// BuildInfoRole reads the role from Collect's own output, whatever the label
// order, so coen doctor stays in step with the exporter.
func TestBuildInfoRole(t *testing.T) {
	for _, role := range []string{"edge", "agent"} {
		if got, ok := BuildInfoRole(render(t, obs.NewState(role))); !ok || got != role {
			t.Fatalf("BuildInfoRole(%s output) = %q, %v", role, got, ok)
		}
	}
	cases := map[string]string{
		`coen_build_info{version="v1",role="edge"} 1`:   "edge",
		"# HELP x\ncoen_build_info{role=\"agent\"} 1\n": "agent",
	}
	for body, want := range cases {
		if got, ok := BuildInfoRole(body); !ok || got != want {
			t.Errorf("BuildInfoRole(%q) = %q, %v; want %q", body, got, ok, want)
		}
	}
	for _, body := range []string{"", "go_goroutines 7", `coen_build_info{version="v1"} 1`, `coen_build_info{role="edge"`} {
		if _, ok := BuildInfoRole(body); ok {
			t.Errorf("BuildInfoRole(%q) should not find a role", body)
		}
	}
}

func TestDrainingGaugeAndParser(t *testing.T) {
	s := obs.NewState("edge")
	out := render(t, s)
	mustContain(t, out, "coen_draining 0")
	if Draining(out) {
		t.Fatal("a running daemon must not parse as draining")
	}
	s.SetDraining()
	out = render(t, s)
	mustContain(t, out, "coen_draining 1")
	if !Draining(out) {
		t.Fatal("a draining daemon must parse as draining")
	}
	if Draining("go_goroutines 3") {
		t.Fatal("no gauge means not draining")
	}
}
