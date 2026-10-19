package e2e

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/obs"
)

// newAgent builds an agent for the stack with the stack's certificate.
func (s *sharedStack) newAgent(t *testing.T) (*agent.Agent, *obs.State) {
	t.Helper()
	state := obs.NewState("agent")
	log, _, _ := obs.NewLogger("error", "text", io.Discard)
	ag, err := agent.New(&config.AgentConfig{
		Edge:      config.EdgeRef{Address: s.addr, CA: s.caPath, Cert: s.agentCert, Key: s.agentKey},
		Routes:    []config.AgentRoute{{Host: "*", Service: s.backend}},
		Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
		Drain:     config.Duration(3 * time.Second),
	}, log, state)
	if err != nil {
		t.Fatal(err)
	}
	return ag, state
}

// The seamless reload, end to end: the running agent's replacement (same
// certificate) connects once the edge has retired the old one, and the edge
// holds the requests that arrive in between (agent_wait). No request fails,
// including one in flight on the old agent. The replacement takes 300ms to
// connect here, as one across the internet takes tens of milliseconds, so
// that requests do arrive while no agent is in the pool.
func TestAgentReplacedWithoutAGap(t *testing.T) {
	st := buildSharedStackWait(t, 0, 0, nil) // the default agent_wait
	old, _ := st.newAgent(t)
	oldCtx, stopOld := context.WithCancel(context.Background())
	oldDone := make(chan struct{})
	go func() { _ = old.Run(oldCtx); close(oldDone) }()
	waitSessions(t, st.edge, 1)

	next, nextState := st.newAgent(t)
	nextCtx, stopNext := context.WithCancel(context.Background())
	nextDone := make(chan struct{})
	t.Cleanup(func() { stopNext(); <-nextDone })
	var retiredAt atomic.Int64
	old.SetOnRetired(func() {
		retiredAt.Store(time.Now().UnixNano())
		time.AfterFunc(300*time.Millisecond, func() { _ = next.Run(nextCtx); close(nextDone) })
	})

	// A steady stream of requests, and one slow one in flight on the old
	// agent across the switch.
	client := st.client()
	var fails, served atomic.Int64
	var wg sync.WaitGroup
	stopLoad := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopLoad:
					return
				default:
				}
				resp, err := client.Get("https://" + st.addr + "/r")
				if err != nil || resp.StatusCode != 200 {
					fails.Add(1)
				} else {
					served.Add(1)
				}
				if resp != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	slow := make(chan int, 1)
	go func() {
		resp, err := client.Get("https://" + st.addr + "/held") // 1.5s before its first event
		if err != nil {
			slow <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		slow <- resp.StatusCode
	}()
	time.Sleep(200 * time.Millisecond)
	stopOld() // the reload: the old agent hands over and drains
	<-oldDone
	for end := time.Now().Add(3 * time.Second); !nextState.Snapshot().TunnelConnected; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the replacement did not connect")
		}
	}
	time.Sleep(200 * time.Millisecond)
	close(stopLoad)
	wg.Wait()

	if retiredAt.Load() == 0 {
		t.Fatal("the old agent never reported being retired")
	}
	if code := <-slow; code != http.StatusOK {
		t.Fatalf("the request in flight on the old agent: %d", code)
	}
	if fails.Load() != 0 {
		t.Fatalf("%d of %d requests failed across the switch", fails.Load(), fails.Load()+served.Load())
	}
	if !nextState.Snapshot().TunnelConnected {
		t.Fatal("the replacement is not connected")
	}
	r := st.edge.Detail().Routes[0]
	if r.Failures.Get(obs.ReasonNoAgent) != 0 || r.Waits == 0 {
		t.Fatalf("no_agent %d, waits %d: requests must have waited for the replacement, and none given up", r.Failures.Get(obs.ReasonNoAgent), r.Waits)
	}
	t.Logf("%d requests served across the switch; %d waited for the replacement", served.Load(), st.edge.Detail().Routes[0].Waits)
}
