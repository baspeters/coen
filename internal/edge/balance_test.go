package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/obs/obstest"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
	"github.com/hashicorp/yamux"
)

func conns(st *obs.State, n int) []*agentConn {
	out := make([]*agentConn, n)
	for i := range out {
		out[i] = &agentConn{fp: "FP", stat: obstest.ConnectAgent(st, "FP", "10.0.0.1:1")}
	}
	return out
}

func TestPickRoundRobinCyclesEvenly(t *testing.T) {
	st := obs.NewState("edge")
	cands := conns(st, 3)
	rs := &routeState{balance: config.BalanceRoundRobin}
	seen := map[*agentConn]int{}
	for i := 0; i < 30; i++ {
		seen[rs.pickNext(cands, map[*agentConn]bool{})]++
	}
	for _, c := range cands {
		if seen[c] != 10 {
			t.Fatalf("round robin not even: %v", seen)
		}
	}
}

func TestPickLeastConnPrefersIdleAndSpreadsTies(t *testing.T) {
	st := obs.NewState("edge")
	cands := conns(st, 3)
	rs := &routeState{balance: config.BalanceLeastConn}
	cands[0].stat.Reserve()
	cands[0].stat.Commit()
	cands[0].stat.Reserve()
	cands[0].stat.Commit()
	cands[1].stat.Reserve()
	cands[1].stat.Commit()
	if got := rs.pickNext(cands, map[*agentConn]bool{}); got != cands[2] {
		t.Fatal("least_conn must pick the session with no open streams")
	}
	// All equal: successive picks rotate instead of always taking the first.
	ties := conns(obs.NewState("edge"), 3)
	seen := map[*agentConn]bool{}
	for i := 0; i < 3; i++ {
		seen[rs.pickNext(ties, map[*agentConn]bool{})] = true
	}
	if len(seen) != 3 {
		t.Fatalf("ties were not spread: %d distinct picks", len(seen))
	}
}

func TestPickSkipsTried(t *testing.T) {
	st := obs.NewState("edge")
	cands := conns(st, 2)
	for _, mode := range []string{config.BalanceLeastConn, config.BalanceRoundRobin} {
		rs := &routeState{balance: mode}
		tried := map[*agentConn]bool{cands[0]: true}
		if got := rs.pickNext(cands, tried); got != cands[1] || !tried[cands[1]] {
			t.Fatalf("%s: tried session picked again, or the pick not marked", mode)
		}
		if got := rs.pickNext(cands, map[*agentConn]bool{cands[0]: true, cands[1]: true}); got != nil {
			t.Fatalf("%s: all tried must return nil", mode)
		}
	}
	// A session cooling down is avoided while another is available, and used
	// when it is the only one left.
	cands[0].coolUntil.Store(time.Now().Add(time.Minute).UnixNano())
	for _, mode := range []string{config.BalanceLeastConn, config.BalanceRoundRobin} {
		rs := &routeState{balance: mode}
		for i := 0; i < 4; i++ {
			if got := rs.pickNext(cands, map[*agentConn]bool{}); got != cands[1] {
				t.Fatalf("%s: a cooling session was preferred", mode)
			}
		}
		if got := rs.pickNext(cands, map[*agentConn]bool{cands[1]: true}); got != cands[0] {
			t.Fatalf("%s: a cooling session must still be used as the last option", mode)
		}
	}
	if (&routeState{}).pickNext(nil, nil) != nil {
		t.Fatal("no candidates must return nil")
	}
}

// A shared fingerprint admits several live sessions; an exclusive one keeps
// the live incumbent.
func TestRegistrySharedFingerprint(t *testing.T) {
	r := newRegistry()
	r.shared["S"] = true
	s1, c1 := newServerSession(t)
	s2, c2 := newServerSession(t)
	s3, c3 := newServerSession(t)
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()
	if !r.register("S", s1) || !r.register("S", s2) {
		t.Fatal("a shared fingerprint must accept a second live session")
	}
	if live, _ := r.candidates([]string{"S"}); len(live) != 2 {
		t.Fatalf("live sessions = %d, want 2", len(live))
	}
	if !r.register("X", s3) {
		t.Fatal("first exclusive session")
	}
	s4, c4 := newServerSession(t)
	defer c4.Close()
	if r.register("X", s4) {
		t.Fatal("an exclusive fingerprint must refuse a second live session")
	}
	_ = s1.Close()
	live, dead := r.candidates([]string{"S", "X"})
	if len(live) != 2 || len(dead) != 1 {
		t.Fatalf("live=%d dead=%d, want 2 and 1", len(live), len(dead))
	}
	if !r.remove("S", s1) || r.remove("S", s1) {
		t.Fatal("remove deletes once")
	}
	if r.remove("S", s3) {
		t.Fatal("removing a session registered under another fingerprint must fail")
	}
}

// When the picked session is dead, the request is retried on another one and
// served; the dead session is evicted.
func TestHandleIngressRetriesOnAnotherSession(t *testing.T) {
	st := obs.NewState("edge")
	rs := &routeState{fingerprints: []string{"A", "B"}, balance: config.BalanceRoundRobin, stats: st.Route("*")}
	e := &Edge{
		cfg:    &config.EdgeConfig{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "*", Value: rs}}),
	}
	// A: a session whose agent end is gone but which the edge has not noticed
	// as closed yet, so OpenStream fails only when tried.
	deadSrv, deadCli := newServerSession(t)
	// B: a working agent that answers every stream.
	liveSrv, liveCli := newServerSession(t)
	defer liveCli.Close()
	go serveEcho(liveCli)
	if res, _ := e.reg.registerConn("A", &agentConn{fp: "A", sess: deadSrv, stat: obstest.ConnectAgent(st, "A", "1")}); res != registered {
		t.Fatal("register")
	}
	if res, _ := e.reg.registerConn("B", &agentConn{fp: "B", sess: liveSrv, stat: obstest.ConnectAgent(st, "B", "2")}); res != registered {
		t.Fatal("register")
	}
	_ = deadCli.Close() // A's agent goes away after registering
	for i := 0; i < 4; i++ {
		client, edgeConn := net.Pipe()
		go e.handleIngress(edgeConn)
		go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		_ = client.Close()
		if !strings.Contains(string(buf[:n]), "ECHO") {
			t.Fatalf("request %d not served by the live agent: %q", i, buf[:n])
		}
	}
	if _, ok := e.reg.get("A"); ok {
		t.Fatal("the dead session was not evicted")
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError); got != 0 {
		t.Fatalf("a retried request must not count as stream_error, got %d", got)
	}
}

// serveEcho answers each stream (after its preamble) with a fixed reply.
func serveEcho(sess *yamux.Session) {
	for {
		s, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			if _, err := tunnel.ReadPreamble(s); err != nil {
				return
			}
			_, _ = s.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nECHO"))
		}()
	}
}

// A shared-certificate connection that never answers the readiness ping (a
// `coen doctor` handshake probe) is never registered, while a real agent is.
func TestSharedSessionMustAnswerPing(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	_ = ingressLn.Close()
	leaf, err := x509.ParseCertificate(agentTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	fp := pki.Fingerprint(leaf)
	e.reg.shared[fp] = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.acceptTunnel(ctx, tunLn)

	// A probe: TLS handshake, then close without speaking yamux.
	probe, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = probe.Close()
	time.Sleep(300 * time.Millisecond)
	if e.reg.size() != 0 {
		t.Fatal("a probe that never answered the ping was registered")
	}

	// A real agent: TLS plus a yamux client, which answers pings.
	conn, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := tunnel.ClientSession(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	deadline := time.Now().Add(3 * time.Second)
	for e.reg.size() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("a real agent with a shared certificate was not registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A draining agent (GoAway) is taken out of the pool without closing its
// session, and the request goes to another agent.
func TestHandleIngressSkipsDrainingAgent(t *testing.T) {
	st := obs.NewState("edge")
	rs := &routeState{fingerprints: []string{"A", "B"}, balance: config.BalanceRoundRobin, stats: st.Route("*")}
	e := &Edge{
		cfg:    &config.EdgeConfig{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "*", Value: rs}}),
	}
	drainSrv, drainCli := newServerSession(t)
	defer drainCli.Close()
	go serveEcho(drainCli)
	if err := drainCli.GoAway(); err != nil {
		t.Fatal(err)
	}
	liveSrv, liveCli := newServerSession(t)
	defer liveCli.Close()
	go serveEcho(liveCli)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: drainSrv, stat: obstest.ConnectAgent(st, "A", "1")})
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: liveSrv, stat: obstest.ConnectAgent(st, "B", "2")})
	// Let the GoAway frame reach the edge side.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := drainSrv.OpenStream(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("GoAway never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := 0; i < 4; i++ {
		client, edgeConn := net.Pipe()
		go e.handleIngress(edgeConn)
		go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) }()
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		_ = client.Close()
		if !strings.Contains(string(buf[:n]), "ECHO") {
			t.Fatalf("request %d not served: %q", i, buf[:n])
		}
	}
	if _, ok := e.reg.get("A"); ok {
		t.Fatal("the draining agent was not taken out of the pool")
	}
	if drainSrv.IsClosed() {
		t.Fatal("a draining agent's session must stay open for its in-flight streams")
	}
}

// Once retired, a session never gets a new stream, and shutdown still closes it.
func TestRetiredSessionGetsNoStreamsButIsClosedOnShutdown(t *testing.T) {
	srv, cli := newServerSession(t)
	defer cli.Close()
	st := obs.NewState("edge")
	e := &Edge{log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: st, reg: newRegistry()}
	c := &agentConn{fp: "FP", sess: srv, stat: obstest.ConnectAgent(st, "FP", "1")}
	e.reg.track("FP", srv) // as serveAgent does before registering
	if res, _ := e.reg.registerConn("FP", c); res != registered {
		t.Fatal("register")
	}
	e.retire(c)
	e.retire(c) // idempotent
	if _, err := openUnlessRetired(c, time.Second); !errors.Is(err, errRetired) {
		t.Fatalf("open after retire = %v, want errRetired", err)
	}
	if live, _ := e.reg.candidates([]string{"FP"}); len(live) != 0 {
		t.Fatal("a retired session must leave the pool")
	}
	if snap := st.Snapshot(); len(snap.Agents) != 1 || !snap.Agents[0].Draining {
		t.Fatalf("a draining session stays listed and marked: %+v", snap.Agents)
	}
	e.reg.closeAll()
	if !srv.IsClosed() {
		t.Fatal("closeAll must close retired sessions too")
	}
}

// Counting the stream at pick time spreads a burst on a least_conn route.
func TestLeastConnBurstSpreadsWithPickTimeAccounting(t *testing.T) {
	st := obs.NewState("edge")
	cands := conns(st, 2)
	rs := &routeState{balance: config.BalanceLeastConn}
	for i := 0; i < 10; i++ {
		rs.pickNext(cands, map[*agentConn]bool{}).stat.Reserve() // what handleIngress does at pick time
	}
	if a, b := cands[0].stat.Active(), cands[1].stat.Active(); a != 5 || b != 5 {
		t.Fatalf("burst spread = %d/%d, want 5/5", a, b)
	}
	cands[0].stat.StreamClosed()
	cands[1].stat.Commit()
	if cands[0].stat.Active() != 4 || st.Detail().AgentStreams["FP"] != 1 {
		t.Fatal("Release undoes only the reservation; the total counts committed streams only")
	}
}

// A reconnect that replaces a closed session leaves exactly one listed session:
// the old one's serveAgent records its own disconnect.
func TestReconnectLeavesNoGhostSession(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	_ = ingressLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.acceptTunnel(ctx, tunLn)
	connect := func() *yamux.Session {
		conn, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := tunnel.ClientSession(conn)
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	waitAgents := func(n int) {
		deadline := time.Now().Add(3 * time.Second)
		for len(e.state.Snapshot().Agents) != n {
			if time.Now().After(deadline) {
				t.Fatalf("listed sessions = %d, want %d", len(e.state.Snapshot().Agents), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	first := connect()
	waitAgents(1)
	_ = first.Close()
	second := connect()
	defer second.Close()
	time.Sleep(300 * time.Millisecond)
	waitAgents(1)
}

// Once shutdown has closed everything, a session still being set up is
// neither tracked nor pooled.
func TestRegistryRefusesSessionsAfterCloseAll(t *testing.T) {
	r := newRegistry()
	s1, c1 := newServerSession(t)
	defer c1.Close()
	if r.track("FP", s1) != trackOK {
		t.Fatal("track before shutdown")
	}
	r.closeAll()
	r.mu.RLock()
	closing := r.closing
	r.mu.RUnlock()
	if !s1.IsClosed() || !closing {
		t.Fatal("closeAll must close tracked sessions and mark the registry")
	}
	s2, c2 := newServerSession(t)
	defer c2.Close()
	defer s2.Close()
	res, _ := r.registerConn("FP", &agentConn{fp: "FP", sess: s2})
	if r.track("FP", s2) != trackClosing || res == registered {
		t.Fatal("no session may be tracked or pooled after closeAll")
	}
	r.drop(s1) // harmless on an already-removed session
}

// Retries within one request reuse its rotation start, so a failing session
// does not make round_robin skip ahead for the next request.
func TestRoundRobinRetriesDoNotAdvanceRotation(t *testing.T) {
	cands := conns(obs.NewState("edge"), 3)
	rs := &routeState{balance: config.BalanceRoundRobin}
	tried := map[*agentConn]bool{}
	turn := rs.nextTurn()
	first := rs.pick(cands, tried, turn)
	second := rs.pick(cands, tried, turn)
	if first == second || first == nil || second == nil {
		t.Fatal("a retry must pick a different session")
	}
	if rs.rr.Load() != 1 {
		t.Fatalf("rotation advanced %d times for one request, want 1", rs.rr.Load())
	}
}

// serveV2 answers streams like a version 2 agent: accept on arrival, read the
// preamble, then echo the request head line back in the response. refuse
// closes streams unaccepted.
func serveV2(sess *yamux.Session, refuse bool) {
	for {
		s, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			if refuse || tunnel.Accept(s) != nil {
				return
			}
			if _, err := tunnel.ReadPreamble(s); err != nil {
				return
			}
			line, _ := bufio.NewReader(s).ReadString('\n')
			body := "GOT " + strings.TrimSpace(line)
			_, _ = fmt.Fprintf(s, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}()
	}
}

func v2Edge(st *obs.State) *Edge {
	return &Edge{
		cfg:    &config.EdgeConfig{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		reg:    newRegistry(),
		routes: route.Build([]route.Entry[*routeState]{{Pattern: "*", Value: &routeState{fingerprints: []string{"A", "B"}, balance: config.BalanceRoundRobin, stats: st.Route("*")}}}),
	}
}

func ask(t *testing.T, e *Edge) string {
	t.Helper()
	client, edgeConn := net.Pipe()
	go e.handleIngress(edgeConn)
	go func() { _, _ = client.Write([]byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")) }()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(client)
	_ = client.Close()
	return string(resp)
}

// A version 2 agent that refuses a stream (closes it without the accept byte,
// as a draining agent does) has not read the request, so the
// edge retries it, head intact, on another agent.
func TestRefusedStreamIsRetriedOnAnotherAgent(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	refSrv, refCli := newServerSession(t)
	defer refCli.Close()
	go serveV2(refCli, true)
	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	go serveV2(okCli, false)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: refSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
	for i := 0; i < 4; i++ {
		if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x HTTP/1.1") {
			t.Fatalf("request %d not retried intact: %q", i, resp)
		}
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError); got != 0 {
		t.Fatalf("retried refusals must not count as failures, got %d", got)
	}
	if st.Detail().AgentStreams["A"] != 0 || st.Detail().AgentStreams["B"] != 4 {
		t.Fatalf("stream totals A=%d B=%d, want 0 and 4", st.Detail().AgentStreams["A"], st.Detail().AgentStreams["B"])
	}
}

// An agent that never accepts has not been sent the request head, so after
// acceptWait the request goes to another agent and is served.
func TestSilentAgentIsRetriedElsewhere(t *testing.T) {
	old := acceptWait
	acceptWait = 100 * time.Millisecond
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	e := v2Edge(st)
	silentSrv, silentCli := newServerSession(t)
	defer silentCli.Close()
	got := make(chan []byte, 8)
	go func() { // takes streams and reads them, but never accepts
		for {
			s, err := silentCli.AcceptStream()
			if err != nil {
				return
			}
			go func() { b, _ := io.ReadAll(s); got <- b }()
		}
	}()
	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	go serveV2(okCli, false)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: silentSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
	for i := 0; i < 4; i++ {
		if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
			t.Fatalf("request %d not retried on the other agent: %q", i, resp)
		}
	}
	if st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError) != 0 {
		t.Fatal("a retried timeout must not count as a failure")
	}
	// The silent agent never accepted, so it was sent nothing at all.
	select {
	case b := <-got:
		if len(b) != 0 {
			t.Fatalf("the silent agent was sent data before accepting: %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the silent agent's stream was not closed")
	}
}

// If an agent's session dies before it accepts, it was never sent the
// request, so the request is retried on another agent and served.
func TestSessionLossBeforeAcceptIsRetried(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	dyingSrv, dyingCli := newServerSession(t)
	go func() {
		s, err := dyingCli.AcceptStream()
		if err != nil {
			return
		}
		_ = s
		_ = dyingCli.Close() // the tunnel drops before the agent accepts
	}()
	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	go serveV2(okCli, false)
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: dyingSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
	rs, _ := e.routes.Match("h")
	rs.rr.Store(0) // turn 0: round robin takes eligible[0], agent A
	if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("want the request served by the other agent, got %q", resp)
	}
}

// Nothing (preamble or request head) goes out before the agent's accept
// byte, and both arrive intact after it.
func TestHeadIsSentOnlyAfterAccept(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	early := make(chan bool, 1)
	go func() {
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		defer s.Close()
		// Before accepting, nothing may arrive.
		_ = s.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _ := s.Read(make([]byte, 1))
		early <- n > 0
		_ = s.SetReadDeadline(time.Time{})
		_ = tunnel.Accept(s)
		if _, err := tunnel.ReadPreamble(s); err != nil {
			return
		}
		line, _ := bufio.NewReader(s).ReadString('\n')
		body := "GOT " + strings.TrimSpace(line)
		_, _ = fmt.Fprintf(s, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	resp := ask(t, e)
	if <-early {
		t.Fatal("request bytes arrived before the agent accepted")
	}
	if !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("not served after accepting: %q", resp)
	}
}

// A cooling session's turns spread evenly over the others under round_robin.
func TestRoundRobinSpreadsACoolingSessionsTurns(t *testing.T) {
	cands := conns(obs.NewState("edge"), 3)
	cands[0].coolDownFor(cooldown)
	rs := &routeState{balance: config.BalanceRoundRobin}
	seen := map[*agentConn]int{}
	for i := 0; i < 40; i++ {
		seen[rs.pickNext(cands, map[*agentConn]bool{})]++
	}
	if seen[cands[0]] != 0 || seen[cands[1]] != 20 || seen[cands[2]] != 20 {
		t.Fatalf("turns not spread evenly: %d/%d/%d", seen[cands[0]], seen[cands[1]], seen[cands[2]])
	}
}

// The per-fingerprint cap counts every open session, draining ones included,
// so retiring sessions and reconnecting cannot pile up sessions without limit.
func TestCapCountsRetiredSessions(t *testing.T) {
	r := newRegistry()
	r.shared["S"] = true
	var keep []*yamux.Session
	defer func() {
		for _, s := range keep {
			_ = s.Close()
		}
	}()
	const n = maxSharedSessions
	for i := 0; i < n; i++ {
		srv, cli := newServerSession(t)
		keep = append(keep, srv, cli)
		r.track("S", srv)
		c := &agentConn{fp: "S", sess: srv}
		if got, _ := r.registerConn("S", c); got != registered {
			t.Fatalf("session %d: %v", i, got)
		}
		r.take("S", srv) // retired: out of the pool, still open
	}
	srv, cli := newServerSession(t)
	keep = append(keep, srv, cli)
	r.track("S", srv)
	if got, _ := r.registerConn("S", &agentConn{fp: "S", sess: srv}); got != refusedCap {
		t.Fatalf("over the cap with retired sessions: %v, want refusedCap", got)
	}
	r.drop(keep[0]) // one goes away: room again
	if got, _ := r.registerConn("S", &agentConn{fp: "S", sess: srv}); got != registered {
		t.Fatalf("after one closed: %v, want registered", got)
	}
}

// Sessions still connecting (tracked, not yet pooled) have their own cap:
// they do not count toward the pooled cap, so a burst of reconnecting agents
// is not refused, but a flood of sessions that never finish connecting is.
func TestCapSessionsStillConnecting(t *testing.T) {
	r := newRegistry()
	r.shared["S"] = true
	var first *yamux.Session
	for i := 0; i < maxSharedSessions; i++ {
		srv, cli := newServerSession(t)
		defer srv.Close()
		defer cli.Close()
		if got := r.track("S", srv); got != trackOK {
			t.Fatalf("session %d: %v, want trackOK", i, got)
		}
		if first == nil {
			first = srv
		}
	}
	srv, cli := newServerSession(t)
	defer srv.Close()
	defer cli.Close()
	if got := r.track("S", srv); got != trackCapped {
		t.Fatalf("over the connecting cap: %v, want trackCapped", got)
	}
	if got := r.track("T", srv); got != trackOK {
		t.Fatalf("another fingerprint is not capped: %v", got)
	}
	r.drop(srv)
	// Pooling one frees a connecting slot; that pooled session counts toward
	// the pooled cap only.
	if got, _ := r.registerConn("S", &agentConn{fp: "S", sess: first}); got != registered {
		t.Fatalf("sessions still connecting must not count toward the pooled cap: %v", got)
	}
	if got := r.track("S", srv); got != trackOK {
		t.Fatalf("after one was pooled: %v, want trackOK", got)
	}
	r.drop(srv)
	r.drop(first)
	if r.pending["S"] != maxSharedSessions-1 || r.joined["S"] != 0 {
		t.Fatalf("pending=%d joined=%d after drops", r.pending["S"], r.joined["S"])
	}
}

// A duplicate of a non-shared certificate is spotted before the ping.
func TestHasLiveExclusive(t *testing.T) {
	r := newRegistry()
	srv, cli := newServerSession(t)
	defer cli.Close()
	if r.hasLiveExclusive("X") {
		t.Fatal("no session yet")
	}
	r.track("X", srv)
	_, _ = r.registerConn("X", &agentConn{fp: "X", sess: srv})
	if !r.hasLiveExclusive("X") {
		t.Fatal("a live exclusive session must be reported")
	}
	r.shared["X"] = true
	if r.hasLiveExclusive("X") {
		t.Fatal("a shared fingerprint never has a duplicate")
	}
	r.shared["X"] = false
	_ = srv.Close()
	if r.hasLiveExclusive("X") {
		t.Fatal("a closed session is not live")
	}
}

// A request waits at most twice acceptWait over all its attempts: with every
// agent stalled it fails then, rather than waiting on each in turn. The
// agents that timed out are kept out of picks for a while.
func TestAcceptDeadlineSpansAllAttempts(t *testing.T) {
	old := acceptWait
	acceptWait = 100 * time.Millisecond
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	fps := []string{"A", "B", "C"}
	e := v2Edge(st)
	rs, _ := e.routes.Match("h")
	rs.fingerprints = fps
	for i, fp := range fps {
		srv, cli := newServerSession(t)
		defer cli.Close()
		go func() { // takes streams but never accepts
			for {
				s, err := cli.AcceptStream()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, s) }()
			}
		}()
		_, _ = e.reg.registerConn(fp, &agentConn{fp: fp, sess: srv, stat: obstest.ConnectAgent(st, fp, strconv.Itoa(i)), v2: true})
	}
	start := time.Now()
	resp := ask(t, e)
	took := time.Since(start)
	if !strings.Contains(resp, "502") {
		t.Fatalf("want 502 once the deadline passes, got %q", resp)
	}
	if took < 2*acceptWait || took > 2*acceptWait+time.Second {
		t.Fatalf("took %v, want about %v", took, 2*acceptWait)
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonStreamError); got != 1 {
		t.Fatalf("stream_error = %d, want 1", got)
	}
	live, _ := e.reg.candidates(fps)
	cooling := 0
	for _, c := range live {
		if time.Now().UnixNano() < c.coolUntil.Load() {
			cooling++
		}
		if c.stat.Active() != 0 {
			t.Fatalf("%s holds %d reservations after the request ended", c.fp, c.stat.Active())
		}
	}
	if cooling != 2 {
		t.Fatalf("%d sessions cooling down, want the 2 that timed out", cooling)
	}
}

// A cooldown is never shortened by a later, shorter one.
func TestCoolDownNeverShortens(t *testing.T) {
	c := conns(obs.NewState("edge"), 1)[0]
	c.coolDownFor(time.Hour)
	long := c.coolUntil.Load()
	c.coolDownFor(time.Second)
	if c.coolUntil.Load() != long {
		t.Fatal("a shorter cooldown replaced a longer one")
	}
	c.coolDownFor(2 * time.Hour)
	if c.coolUntil.Load() <= long {
		t.Fatal("a longer cooldown did not extend it")
	}
}

// A session whose agent has stopped acknowledging opens blocks yamux's open
// once its backlog is full. The open is bounded by the wait it is given; the
// open given up on finishes later, its stream closed and its count released.
func TestOpenIsBoundedOnAStalledSession(t *testing.T) {
	srv, cli := newServerSession(t)
	defer srv.Close()
	defer cli.Close()
	const backlog = 256 // yamux's default AcceptBacklog
	for i := 0; i < backlog; i++ {
		if _, err := srv.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	c := &agentConn{fp: "A", sess: srv}
	start := time.Now()
	if _, err := openUnlessRetired(c, 100*time.Millisecond); !errors.Is(err, errOpenTimeout) {
		t.Fatalf("err = %v, want errOpenTimeout", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the open took %v despite its wait", d)
	}
	// While that open is still blocked, the next fails at once instead of
	// adding another blocked goroutine.
	start = time.Now()
	if _, err := openUnlessRetired(c, time.Second); !errors.Is(err, errOpenBlocked) {
		t.Fatalf("err = %v, want errOpenTimeout", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("an open on a session with a blocked open took %v", d)
	}
	// The agent catches up: the abandoned open completes and is released.
	go func() {
		for {
			s, err := cli.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, s); _ = s.Close() }()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		n := c.opening + c.stuck
		c.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the abandoned open was never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Only the backlog streams stay open: the abandoned open's was closed.
	for srv.NumStreams() != backlog {
		if time.Now().After(deadline) {
			t.Fatalf("open streams = %d, want %d", srv.NumStreams(), backlog)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An agent that joins while a request is being retried still gets its turn
// once the sessions listed at the start have all failed.
func TestAgentJoiningDuringRetriesIsTried(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	go serveV2(okCli, false)
	refSrv, refCli := newServerSession(t)
	defer refCli.Close()
	go func() { // refuses, but first lets agent B join
		s, err := refCli.AcceptStream()
		if err != nil {
			return
		}
		_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
		_ = s.Close()
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: refSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("the agent that joined was not tried: %q", resp)
	}
}

// A cooling session that serves a stream again is back in normal picks at
// once, rather than after its cooldown.
func TestSuccessClearsCooldown(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go serveV2(cli, false)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	c.coolDownFor(time.Hour)
	if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("the only session, though cooling, must still serve: %q", resp)
	}
	if c.coolUntil.Load() != 0 {
		t.Fatal("a successful stream must clear the cooldown")
	}
}

// The stream open and the accept wait share one budget: an open that waited
// for a free backlog slot leaves the accept wait only what is left.
func TestAttemptBudgetCoversOpenAndAccept(t *testing.T) {
	srv, cli := newServerSession(t)
	defer srv.Close()
	defer cli.Close()
	const backlog = 256 // yamux's default AcceptBacklog
	for i := 0; i < backlog; i++ {
		if _, err := srv.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	go func() { // frees one backlog slot after a while, then accepts nothing more
		time.Sleep(150 * time.Millisecond)
		_, _ = cli.AcceptStream()
	}()
	st := obs.NewState("edge")
	e := v2Edge(st)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	c.stat.Reserve()
	start := time.Now()
	_, outcome, err := e.tryAgent(c, []byte("p"), []byte("h"), 200*time.Millisecond)
	took := time.Since(start)
	if outcome != attemptFailed {
		t.Fatalf("outcome = %v (%v), want attemptFailed", outcome, err)
	}
	// Separate waits would take the open's 150ms plus a full 200ms accept.
	if took < 190*time.Millisecond || took > 300*time.Millisecond {
		t.Fatalf("the attempt took %v, want about its 200ms budget", took)
	}
}

// A session that closed after it was listed is gone, not a stream error: the
// attempt counts as unavailable and the session is evicted.
func TestClosedSessionIsUnavailable(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	for _, v2 := range []bool{false, true} {
		srv, cli := newServerSession(t)
		c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: v2}
		_, _ = e.reg.registerConn("A", c)
		_ = cli.Close()
		_ = srv.Close()
		c.stat.Reserve()
		if _, outcome, err := e.tryAgent(c, []byte("p"), []byte("h"), time.Second); outcome != attemptUnavailable {
			t.Fatalf("v2=%v: outcome = %v (%v), want attemptUnavailable", v2, outcome, err)
		}
		if live, _ := e.reg.candidates([]string{"A"}); len(live) != 0 {
			t.Fatalf("v2=%v: the closed session is still pooled", v2)
		}
		if c.stat.Active() != 0 {
			t.Fatalf("v2=%v: the reservation was not released", v2)
		}
	}
}

// A round_robin rotation starts at the first session.
func TestRoundRobinStartsAtFirstSession(t *testing.T) {
	cands := conns(obs.NewState("edge"), 3)
	rs := &routeState{balance: config.BalanceRoundRobin}
	for i := 0; i < 3; i++ {
		if got := rs.pickNext(cands, map[*agentConn]bool{}); got != cands[i] {
			t.Fatalf("request %d went to the wrong session", i)
		}
	}
}

// An accept wait cut short by the request's deadline does not mark the
// session as stalled.
func TestShortWaitDoesNotMarkStalled(t *testing.T) {
	old := acceptWait
	acceptWait = time.Second
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() { // takes streams but never accepts
		for {
			s, err := cli.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, s) }()
		}
	}()
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	c.stat.Reserve()
	if _, outcome, _ := e.tryAgent(c, []byte("p"), []byte("h"), acceptWait/10); outcome != attemptFailed {
		t.Fatalf("outcome = %v, want attemptFailed", outcome)
	}
	if until := c.coolUntil.Load(); time.Until(time.Unix(0, until)) > cooldown {
		t.Fatal("a wait cut short by the deadline marked the session stalled")
	}
	c.stat.Reserve()
	if _, outcome, _ := e.tryAgent(c, []byte("p"), []byte("h"), 3*acceptWait/4); outcome != attemptFailed {
		t.Fatalf("outcome = %v, want attemptFailed", outcome)
	}
	if until := c.coolUntil.Load(); time.Until(time.Unix(0, until)) <= cooldown {
		t.Fatal("a session silent for half of acceptWait must be marked stalled")
	}
}

// With no other session to try, an attempt may use the rest of the request's
// time: a slow but working agent that accepts after acceptWait is served.
func TestLastCandidateGetsTheRemainingTime(t *testing.T) {
	old := acceptWait
	acceptWait = 100 * time.Millisecond
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() {
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		defer s.Close()
		time.Sleep(3 * acceptWait / 2) // slow, but within the request's 2*acceptWait
		if tunnel.Accept(s) != nil {
			return
		}
		if _, err := tunnel.ReadPreamble(s); err != nil {
			return
		}
		line, _ := bufio.NewReader(s).ReadString('\n')
		body := "GOT " + strings.TrimSpace(line)
		_, _ = fmt.Fprintf(s, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("the only agent, slow to accept, was not served: %q", resp)
	}
}

// A wrong first byte is a protocol fault: the session is dropped, not cooled.
func TestBadAcceptByteEvicts(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() {
		s, err := cli.AcceptStream()
		if err != nil {
			return
		}
		_, _ = s.Write([]byte{'X'})
	}()
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	c.stat.Reserve()
	if _, outcome, err := e.tryAgent(c, []byte("p"), []byte("h"), time.Second); outcome != attemptFailed || !errors.Is(err, tunnel.ErrBadAccept) {
		t.Fatalf("outcome = %v, err = %v; want attemptFailed, ErrBadAccept", outcome, err)
	}
	if live, _ := e.reg.candidates([]string{"A"}); len(live) != 0 {
		t.Fatal("a session that broke the protocol is still pooled")
	}
}

// An evicted session leaves status and metrics at once, before its close
// completes in the background.
func TestEvictUpdatesStatusAtOnce(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	if n := len(st.Snapshot().Agents); n != 1 {
		t.Fatalf("agents = %d, want 1", n)
	}
	e.evict(c)
	if n := len(st.Snapshot().Agents); n != 0 {
		t.Fatalf("an evicted session is still listed: %d", n)
	}
	if live, _ := e.reg.candidates([]string{"A"}); len(live) != 0 {
		t.Fatal("an evicted session is still pooled")
	}
	select {
	case <-srv.CloseChan():
	case <-time.After(2 * time.Second):
		t.Fatal("the evicted session was never closed")
	}
}

// A stalled agent retried as the last listed candidate does not get the
// rest of the request's time when another agent has joined meanwhile: the
// newcomer is tried and serves the request.
func TestStalledLastCandidateYieldsToANewcomer(t *testing.T) {
	old := acceptWait
	acceptWait = 100 * time.Millisecond
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	e := v2Edge(st)
	stalledSrv, stalledCli := newServerSession(t)
	defer stalledCli.Close()
	go func() { // takes streams but never accepts
		for {
			s, err := stalledCli.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, s) }()
		}
	}()
	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	go serveV2(okCli, false)
	e.reg.shared["B"] = true // the replacement joins while B is still connected
	refSrv, refCli := newServerSession(t)
	defer refCli.Close()
	go func() { // B refuses, but its replacement joins first
		s, err := refCli.AcceptStream()
		if err != nil {
			return
		}
		_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "3"), v2: true})
		_ = s.Close()
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: stalledSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: refSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
	rs, _ := e.routes.Match("h")
	rs.rr.Store(1) // turn 1: B (the refusing one) first, then A, then the newcomer
	start := time.Now()
	if resp := ask(t, e); !strings.Contains(resp, "GOT GET /x") {
		t.Fatalf("the newcomer was not tried: %q", resp)
	}
	if d := time.Since(start); d > 3*acceptWait/2 {
		t.Fatalf("took %v: the stalled agent held the request past one acceptWait", d)
	}
}

// A pooled session whose agent has sent GoAway is retired by the probe; a
// healthy one stays pooled and gets only an empty stream, closed at once.
func TestRetireGoingAway(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	goneSrv, goneCli := newServerSession(t)
	defer goneCli.Close()
	gone := &agentConn{fp: "A", sess: goneSrv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", gone)
	if err := goneCli.GoAway(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.retireGoingAway("A")
		if live, _ := e.reg.candidates([]string{"A"}); len(live) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a session that sent GoAway was not retired")
		}
		time.Sleep(10 * time.Millisecond)
	}

	okSrv, okCli := newServerSession(t)
	defer okCli.Close()
	got := make(chan int, 1)
	go func() {
		s, err := okCli.AcceptStream()
		if err != nil {
			return
		}
		b, _ := io.ReadAll(s)
		got <- len(b)
	}()
	_, _ = e.reg.registerConn("B", &agentConn{fp: "B", sess: okSrv, stat: obstest.ConnectAgent(st, "B", "2"), v2: true})
	e.retireGoingAway("B")
	if live, _ := e.reg.candidates([]string{"B"}); len(live) != 1 {
		t.Fatal("a healthy session left the pool")
	}
	select {
	case n := <-got:
		if n != 0 {
			t.Fatalf("the probe stream carried %d bytes, want none", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the probe stream was not closed")
	}
}

// A lone agent that went silent may hold one request for the whole deadline,
// but once it is marked stalled, the next requests wait only acceptWait.
func TestStalledLoneAgentDoesNotHoldEveryRequest(t *testing.T) {
	old := acceptWait
	acceptWait = 100 * time.Millisecond
	defer func() { acceptWait = old }()
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	defer cli.Close()
	go func() { // takes streams but never accepts
		for {
			s, err := cli.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, s) }()
		}
	}()
	_, _ = e.reg.registerConn("A", &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true})
	start := time.Now()
	_ = ask(t, e)
	if d := time.Since(start); d < 2*acceptWait-10*time.Millisecond {
		t.Fatalf("first request took %v, want the whole deadline (%v)", d, 2*acceptWait)
	}
	start = time.Now()
	_ = ask(t, e)
	if d := time.Since(start); d > 3*acceptWait/2 {
		t.Fatalf("second request took %v, want about one acceptWait (%v)", d, acceptWait)
	}
}

// A drain acknowledgement does not wait for opens already given up on: their
// streams are closed unused, so they cannot reach the agent with a request.
func TestDrainAckSkipsAbandonedOpens(t *testing.T) {
	srv, cli := newServerSession(t)
	defer srv.Close()
	defer cli.Close()
	for i := 0; i < 256; i++ { // fill yamux's default AcceptBacklog
		if _, err := srv.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	st := obs.NewState("edge")
	e := v2Edge(st)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	if _, err := openUnlessRetired(c, 50*time.Millisecond); !errors.Is(err, errOpenTimeout) {
		t.Fatalf("err = %v, want errOpenTimeout", err)
	}
	start := time.Now()
	e.retireForDrain(c)
	if d := time.Since(start); d >= tunnel.RetireWait {
		t.Fatalf("the drain acknowledgement waited %v for an abandoned open", d)
	}
}

// An open that times out marks the session stalled whoever opened it, and so
// does a later open refused because one is still blocked.
func TestOpenTimeoutMarksStalled(t *testing.T) {
	srv, cli := newServerSession(t)
	defer srv.Close()
	defer cli.Close()
	for i := 0; i < 256; i++ { // fill yamux's default AcceptBacklog
		if _, err := srv.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	st := obs.NewState("edge")
	e := v2Edge(st)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	e.retireGoingAway("A") // the probe's short open times out
	if live, _ := e.reg.candidates([]string{"A"}); len(live) != 1 {
		t.Fatal("a stalled session is not going away")
	}
	if time.Until(time.Unix(0, c.coolUntil.Load())) <= cooldown {
		t.Fatal("an open timeout did not mark the session stalled")
	}
	c.coolUntil.Store(0)
	c.stat.Reserve()
	if _, outcome, err := e.tryAgent(c, []byte("p"), []byte("h"), time.Second); outcome != attemptFailed || !errors.Is(err, errOpenBlocked) {
		t.Fatalf("outcome = %v, err = %v; want attemptFailed, errOpenBlocked", outcome, err)
	}
	if c.coolUntil.Load() == 0 {
		t.Fatal("a blocked session was not kept out of picks")
	}
}

// A newcomer is not refused when the incumbent closed while being probed.
func TestDuplicateRecheckedAfterProbe(t *testing.T) {
	st := obs.NewState("edge")
	e := v2Edge(st)
	srv, cli := newServerSession(t)
	c := &agentConn{fp: "A", sess: srv, stat: obstest.ConnectAgent(st, "A", "1"), v2: true}
	_, _ = e.reg.registerConn("A", c)
	_ = cli.Close()
	<-srv.CloseChan()
	if e.duplicateAfterProbe("A") {
		t.Fatal("a closed incumbent still counts as a duplicate")
	}
}
