package metrics

import (
	"strings"

	"github.com/baspeters/coen/internal/obs"
)

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect turns a State's Detail into metric families for the daemon's role.
func Collect(d obs.Detail, version string) []Family {
	role := d.Role
	fams := []Family{
		{Name: "coen_build_info", Help: "Build information; always 1.", Type: Gauge,
			Samples: []Sample{{Labels: []Label{{"role", role}, {"version", version}}, Value: 1}}},
		{Name: "coen_streams_peak", Help: "Highest number of concurrent streams since start.", Type: Gauge,
			Samples: []Sample{{Value: float64(d.MaxStreams)}}},
		{Name: "coen_draining", Help: "1 once shutdown has started and in-flight streams are draining, else 0.", Type: Gauge,
			Samples: []Sample{{Value: boolf(d.Draining)}}},
	}

	if !d.StartTime.IsZero() {
		fams = append(fams, Family{Name: "coen_process_start_time_seconds", Help: "Start time of the daemon since the Unix epoch, in seconds.", Type: Gauge,
			Samples: []Sample{{Value: float64(d.StartTime.Unix())}}})
	}

	active := Family{Name: "coen_streams_active", Help: "Streams currently open, by route.", Type: Gauge}
	total := Family{Name: "coen_streams_total", Help: "Streams opened since start, by route.", Type: Counter}
	h3 := Family{Name: "coen_streams_http3_total", Help: "Streams opened since start for HTTP/3 requests, by route (included in coen_streams_total). A stream carries one or more of a connection's requests in turn.", Type: Counter}
	waits := Family{Name: "coen_ingress_agent_waits_total", Help: "Requests that found no agent to take them and waited for one (agent_wait), by route; those still without one when the wait ran out are also counted as no_agent in coen_ingress_rejected_total.", Type: Counter}
	h3req := Family{Name: "coen_http3_requests_total", Help: "HTTP/3 requests sent to the service since start, by route, over the streams counted in coen_streams_http3_total.", Type: Counter}
	bytes := Family{Name: "coen_stream_bytes_total", Help: "Bytes carried by streams as they flow, by route and direction (in: client to backend, out: backend to client).", Type: Counter}
	for _, r := range d.Routes {
		rl := Label{"route", r.Pattern}
		active.Samples = append(active.Samples, Sample{Labels: []Label{rl}, Value: float64(r.Active)})
		total.Samples = append(total.Samples, Sample{Labels: []Label{rl}, Value: float64(r.Total)})
		h3.Samples = append(h3.Samples, Sample{Labels: []Label{rl}, Value: float64(r.TotalH3)})
		h3req.Samples = append(h3req.Samples, Sample{Labels: []Label{rl}, Value: float64(r.ReqH3)})
		waits.Samples = append(waits.Samples, Sample{Labels: []Label{rl}, Value: float64(r.Waits)})
		bytes.Samples = append(bytes.Samples,
			Sample{Labels: []Label{{"direction", "in"}, rl}, Value: float64(r.BytesIn)},
			Sample{Labels: []Label{{"direction", "out"}, rl}, Value: float64(r.BytesOut)})
	}
	fams = append(fams, active, total, bytes)
	if role == "edge" {
		fams = append(fams, h3, h3req, waits)
	}

	hs := Family{Name: "coen_tunnel_handshakes_total", Type: Counter,
		Samples: []Sample{
			{Labels: []Label{{"result", "ok"}}, Value: float64(d.HandshakeOK)},
			{Labels: []Label{{"result", "fail"}}, Value: float64(d.HandshakeFail)},
		}}

	switch role {
	case "edge":
		hs.Help = "Incoming agent tunnel connections, by result: ok (authenticated and registered), fail (authenticated but not allowed by any route, or not answering the readiness ping), duplicate (authenticated but refused because a live session owns the fingerprint), capped (refused at the per-certificate session cap), rejected (refused at the TLS handshake)."
		hs.Samples = append(hs.Samples,
			Sample{Labels: []Label{{"result", "rejected"}}, Value: float64(d.HandshakeRejected)},
			Sample{Labels: []Label{{"result", "duplicate"}}, Value: float64(d.HandshakeDup)},
			Sample{Labels: []Label{{"result", "capped"}}, Value: float64(d.HandshakeCapped)})
		fams = append(fams, edgeAgents(d)...)
		fams = append(fams, hs,
			Family{Name: "coen_ingress_header_timeouts_total", Help: "Ingress connections closed at read_header_timeout without sending any request byte, such as idle browser preconnects. Not rejected requests.", Type: Counter,
				Samples: []Sample{{Value: float64(d.HeaderTimeouts)}}},
			failures("coen_ingress_rejected_total", "Ingress requests the edge could not forward, by route and reason.", d, obs.EdgeUnroutedReasons, obs.EdgeRouteReasons))
	case "agent":
		hs.Help = "Attempts to connect to the edge, by result: ok (connected), fail (the dial, the TLS handshake, or the edge pin check failed)."
		fams = append(fams, hs,
			Family{Name: "coen_tunnel_up", Help: "Whether the tunnel to the edge is established (1) or not (0).", Type: Gauge,
				Samples: []Sample{{Value: boolf(d.TunnelConnected)}}},
			Family{Name: "coen_tunnel_reconnects_total", Help: "Reconnect attempts to the edge since start.", Type: Counter,
				Samples: []Sample{{Value: float64(d.Reconnects)}}},
			failures("coen_stream_errors_total", "Streams the agent could not serve, by route and reason.", d, obs.AgentUnroutedReasons, obs.AgentRouteReasons))
	default:
		// A State without a role (tests, embedding) gets the shared families.
		hs.Help = "Tunnel connections, by result."
		fams = append(fams, hs)
	}
	return fams
}

// edgeAgents reports each agent the config allows as connected (1) or not (0).
// The edge refuses any fingerprint outside the config, which is never reloaded
// at runtime, so the configured set covers every agent that can connect.
func edgeAgents(d obs.Detail) []Family {
	connectedFP := make(map[string]bool, len(d.Agents)) // any session, draining included
	sessions := make(map[string]int, len(d.Agents))     // sessions taking new traffic
	active := make(map[string]int64, len(d.Agents))     // open streams, draining sessions included
	for _, a := range d.Agents {
		connectedFP[a.Fingerprint] = true
		if !a.Draining {
			sessions[a.Fingerprint]++
		}
		active[a.Fingerprint] += a.ActiveStreams
	}
	connected := Family{Name: "coen_agent_connected", Help: "Whether an agent is connected (1) or not (0), by certificate fingerprint; a draining agent still counts as connected (see coen_agent_sessions for agents taking new traffic).", Type: Gauge}
	count := Family{Name: "coen_agent_sessions", Help: "Tunnel sessions taking new traffic per agent fingerprint (draining ones excluded); more than 1 only with allow_shared_cert.", Type: Gauge}
	open := Family{Name: "coen_agent_streams_active", Help: "Streams open or being set up right now, by agent fingerprint (summed over its sessions); the load least_conn balances on.", Type: Gauge}
	total := Family{Name: "coen_agent_streams_total", Help: "Streams opened since start, by agent fingerprint; shows how load is balanced.", Type: Counter}
	for _, fp := range d.ExpectedAgents {
		l := []Label{{"fingerprint", fp}}
		connected.Samples = append(connected.Samples, Sample{Labels: l, Value: boolf(connectedFP[fp])})
		count.Samples = append(count.Samples, Sample{Labels: l, Value: float64(sessions[fp])})
		open.Samples = append(open.Samples, Sample{Labels: l, Value: float64(active[fp])})
		total.Samples = append(total.Samples, Sample{Labels: l, Value: float64(d.AgentStreams[fp])})
	}
	return []Family{connected, count, open, total}
}

// failures builds a reason-labelled counter family: every reason the role is
// listed as recording, starting at 0, plus any other reason that is non-zero
// (so a reason missing from the lists is still exported once it occurs).
// Unrouted failures carry no route label; routed ones carry the route pattern.
func failures(name, help string, d obs.Detail, unrouted, routed []obs.Reason) Family {
	f := Family{Name: name, Help: help, Type: Counter}
	for _, r := range reported(unrouted, d.UnroutedFailures) {
		f.Samples = append(f.Samples, Sample{Labels: []Label{{"reason", r.String()}}, Value: float64(d.UnroutedFailures.Get(r))})
	}
	for _, rt := range d.Routes {
		for _, r := range reported(routed, rt.Failures) {
			f.Samples = append(f.Samples, Sample{Labels: []Label{{"reason", r.String()}, {"route", rt.Pattern}}, Value: float64(rt.Failures.Get(r))})
		}
	}
	return f
}

// reported returns the listed reasons plus every other non-zero one.
func reported(listed []obs.Reason, counts obs.ReasonCounts) []obs.Reason {
	out := append([]obs.Reason(nil), listed...)
	seen := make(map[obs.Reason]bool, len(listed))
	for _, r := range listed {
		seen[r] = true
	}
	for r := range counts {
		if reason := obs.Reason(r); counts[r] != 0 && !seen[reason] {
			out = append(out, reason)
		}
	}
	return out
}

// Draining reports whether a text exposition body has coen_draining set to 1.
func Draining(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, "coen_draining "); ok {
			return strings.TrimSpace(v) == "1"
		}
	}
	return false
}

// BuildInfoRole finds the coen_build_info sample in a text exposition body and
// returns its role label, so a client (coen doctor) can recognise a coen
// endpoint without depending on label order.
func BuildInfoRole(body string) (role string, ok bool) {
	for _, line := range strings.Split(body, "\n") {
		rest, found := strings.CutPrefix(line, "coen_build_info{")
		if !found {
			continue
		}
		labels, _, found := strings.Cut(rest, "}")
		if !found {
			return "", false
		}
		for _, kv := range strings.Split(labels, ",") {
			name, value, _ := strings.Cut(kv, "=")
			if name == "role" {
				return strings.Trim(value, `"`), true
			}
		}
		return "", false
	}
	return "", false
}
