package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/tunnel"
)

// stubAgent connects to the edge's tunnel and answers every stream with 200.
func stubAgent(t *testing.T, tunAddr string, agentTLS *tls.Config) {
	t.Helper()
	raw, err := tls.Dial("tcp", tunAddr, agentTLS)
	if err != nil {
		t.Error(err)
		return
	}
	sess, err := tunnel.ClientSession(raw)
	if err != nil {
		t.Error(err)
		return
	}
	t.Cleanup(func() { _ = sess.Close() })
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				if tunnel.Accept(s) != nil {
					return
				}
				if _, err := tunnel.ReadPreamble(s); err != nil {
					return
				}
				_, _ = bufio.NewReader(s).ReadString('\n')
				_, _ = io.WriteString(s, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(stream)
		}
	}()
}

// get sends one request to the ingress and returns the response and how long
// it took.
func ingressGet(t *testing.T, addr string) (string, time.Duration) {
	t.Helper()
	start := time.Now()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	b, _ := io.ReadAll(c)
	return string(b), time.Since(start)
}

func routeStats(e *Edge) obs.RouteSnapshot { return e.state.Detail().Routes[0] }

// A request that finds no agent waits for one, and is served once it joins.
func TestRequestWaitsForAnAgent(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
	time.AfterFunc(300*time.Millisecond, func() { stubAgent(t, tunLn.Addr().String(), agentTLS) })
	resp, took := ingressGet(t, ingressLn.Addr().String())
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("got %q", resp)
	}
	if took < 250*time.Millisecond || took > 3*time.Second {
		t.Fatalf("served after %v; the agent joined after 300ms", took)
	}
	if s := routeStats(e); s.Waits != 1 || s.Failures.Get(obs.ReasonNoAgent) != 0 {
		t.Fatalf("waits %d, no_agent %d", s.Waits, s.Failures.Get(obs.ReasonNoAgent))
	}
}

// With no agent coming, the request gets its 502 once agent_wait runs out;
// with agent_wait 0, at once.
func TestRequestGivesUpAfterAgentWait(t *testing.T) {
	for _, wait := range []time.Duration{400 * time.Millisecond, 0} {
		e, tunLn, ingressLn, _ := newTestEdge(t)
		e.cfg.AgentWait = config.NewDuration(wait)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
		resp, took := ingressGet(t, ingressLn.Addr().String())
		cancel()
		if !strings.Contains(resp, "502 Bad Gateway") {
			t.Fatalf("wait %v: got %q", wait, resp)
		}
		if took < wait || took > wait+2*time.Second {
			t.Fatalf("wait %v: answered after %v", wait, took)
		}
		s := routeStats(e)
		wantWaits := int64(1)
		if wait == 0 {
			wantWaits = 0
		}
		if s.Waits != wantWaits || s.Failures.Get(obs.ReasonNoAgent) != 1 {
			t.Fatalf("wait %v: waits %d, no_agent %d", wait, s.Waits, s.Failures.Get(obs.ReasonNoAgent))
		}
	}
}

// A request whose client goes away stops waiting.
func TestAgentWaitEndsWithTheRequest(t *testing.T) {
	e, _, _, _ := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(10 * time.Second)
	rs, _ := e.routes.Match("app.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, refused := e.dispatch(ctx, rs, "c1", "127.0.0.1:1", "app.example.com", []byte("GET / HTTP/1.1\r\n\r\n"), e.log)
	if refused != noAgent || time.Since(start) > 2*time.Second {
		t.Fatalf("got %v after %v", refused, time.Since(start))
	}
}

func TestAgentWaitConfig(t *testing.T) {
	c := &config.EdgeConfig{}
	if c.AgentWaitDuration() != config.DefaultAgentWait {
		t.Fatal("unset: the default")
	}
	c.AgentWait = config.NewDuration(0)
	if c.AgentWaitDuration() != 0 {
		t.Fatal("0 turns it off")
	}
}

// refusingAgent takes every stream as a draining agent does: it closes it
// without the accept byte.
func refusingAgent(t *testing.T, tunAddr string, agentTLS *tls.Config) {
	t.Helper()
	raw, err := tls.Dial("tcp", tunAddr, agentTLS)
	if err != nil {
		t.Error(err)
		return
	}
	sess, err := tunnel.ClientSession(raw)
	if err != nil {
		t.Error(err)
		return
	}
	t.Cleanup(func() { _ = sess.Close() })
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			_ = stream.Close()
		}
	}()
}

// An agent that refuses every stream (draining, or its queue full) is no
// agent to serve the request: it waits, then gets 502 as no_agent.
func TestRequestWithOnlyARefusingAgent(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(200 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
	refusingAgent(t, tunLn.Addr().String(), agentTLS)
	for end := time.Now().Add(2 * time.Second); e.reg.size() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the agent did not register")
		}
	}
	resp, _ := ingressGet(t, ingressLn.Addr().String())
	if !strings.Contains(resp, "502 Bad Gateway") {
		t.Fatalf("got %q", resp)
	}
	if s := routeStats(e); s.Waits != 1 || s.Failures.Get(obs.ReasonNoAgent) != 1 {
		t.Fatalf("waits %d, no_agent %d", s.Waits, s.Failures.Get(obs.ReasonNoAgent))
	}
}

// An agent that refuses one stream (a briefly full queue) and then serves:
// the waiting request is tried again within agentRetry and served, rather
// than waiting out agent_wait for a new session that never joins.
func TestRequestRetriedWhileWaiting(t *testing.T) {
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
	raw, err := tls.Dial("tcp", tunLn.Addr().String(), agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := tunnel.ClientSession(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go func() {
		for n := 0; ; n++ {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			if n == 0 {
				_ = stream.Close() // refused: no accept byte
				continue
			}
			go func(s net.Conn) {
				defer s.Close()
				if tunnel.Accept(s) != nil {
					return
				}
				if _, err := tunnel.ReadPreamble(s); err != nil {
					return
				}
				_, _ = bufio.NewReader(s).ReadString('\n')
				_, _ = io.WriteString(s, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(stream)
		}
	}()
	for end := time.Now().Add(2 * time.Second); e.reg.size() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the agent did not register")
		}
	}
	resp, took := ingressGet(t, ingressLn.Addr().String())
	if !strings.Contains(resp, "200 OK") || took > 2*time.Second {
		t.Fatalf("got %q after %v", resp, took)
	}
}

// Waiting ends when the edge shuts down.
func TestAgentWaitEndsWithTheEdge(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { _ = e.Serve(ctx, tunLn, ingressLn); close(served) }()
	time.AfterFunc(300*time.Millisecond, cancel)
	resp, took := ingressGet(t, ingressLn.Addr().String())
	if !strings.Contains(resp, "502") || took > 5*time.Second {
		t.Fatalf("got %q after %v", resp, took)
	}
	<-served
}

// The request head cannot be sent after the agent took the stream. The
// agent may have part of it, so the edge answers 502 (a stream error)
// without trying another agent or waiting.
func TestRequestHeadSendFails(t *testing.T) {
	defer func(old func(net.Conn, []byte) (int, error)) { sendHead = old }(sendHead)
	sendHead = func(net.Conn, []byte) (int, error) { return 0, io.ErrClosedPipe }
	e, tunLn, ingressLn, agentTLS := newTestEdge(t)
	e.cfg.AgentWait = config.NewDuration(5 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
	stubAgent(t, tunLn.Addr().String(), agentTLS)
	for end := time.Now().Add(2 * time.Second); e.reg.size() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the agent did not register")
		}
	}
	resp, took := ingressGet(t, ingressLn.Addr().String())
	if !strings.Contains(resp, "502 Bad Gateway") || took > 2*time.Second {
		t.Fatalf("got %q after %v", resp, took)
	}
	if s := routeStats(e); s.Failures.Get(obs.ReasonStreamError) != 1 || s.Waits != 0 {
		t.Fatalf("stream_error %d, waits %d", s.Failures.Get(obs.ReasonStreamError), s.Waits)
	}
}
