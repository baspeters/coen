package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/agent"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/edge"
	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

// lbAgent describes one agent in a balancing test: its name (the backend
// identity), and which certificate it uses (agents with the same cert share it).
type lbAgent struct{ name, cert string }

type lbStack struct {
	addr   string
	edge   *obs.State
	stop   map[string]context.CancelFunc // per agent
	certFP map[string]string             // cert name -> fingerprint
}

// startNamedBackend answers every HTTP request with its name; a WebSocket
// upgrade is held open (and echoed) so it counts as an open stream.
func startNamedBackend(t *testing.T, name string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
					fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Backend: %s\r\n\r\n", name)
					_, _ = io.Copy(c, br)
					return
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(name), name)
			}(c)
		}
	}()
	return ln
}

// buildLBStack starts an edge with one route on "*" whose agents are given by
// route(certFP), and the listed agents, each with its own backend.
func buildLBStack(t *testing.T, agents []lbAgent, route func(certFP map[string]string) config.EdgeRoute) *lbStack {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := writeFile(t, dir, "ca.crt", ca.CertPEM())
	ecPEM, ekPEM, _ := ca.IssueServer("127.0.0.1")
	edgeCertPath := writeFile(t, dir, "edge.crt", ecPEM)
	edgeKeyPath := writeFile(t, dir, "edge.key", ekPEM)
	st := &lbStack{edge: obs.NewState("edge"), stop: map[string]context.CancelFunc{}, certFP: map[string]string{}}
	certPaths := map[string][2]string{}
	for _, a := range agents {
		if _, ok := certPaths[a.cert]; ok {
			continue
		}
		cPEM, kPEM, _ := ca.IssueClient(a.cert)
		certPaths[a.cert] = [2]string{writeFile(t, dir, a.cert+".crt", cPEM), writeFile(t, dir, a.cert+".key", kPEM)}
		st.certFP[a.cert] = fingerprintOf(t, cPEM)
	}
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	edgeCert, _ := tls.X509KeyPair(ecPEM, ekPEM)
	edgeLog, _, _ := obs.NewLogger("error", "text", io.Discard)
	e, err := edge.New(&config.EdgeConfig{
		Ingress: config.IngressConfig{Mode: "proxied"},
		Tunnel:  config.TunnelServerConfig{CA: caPath, Cert: edgeCertPath, Key: edgeKeyPath},
		Routes:  []config.EdgeRoute{route(st.certFP)},
	}, edgeLog, st.edge)
	if err != nil {
		t.Fatal(err)
	}
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn := tls.NewListener(tcp, tunnel.ServerTLSConfig(pool, edgeCert))
	ingressLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = e.Serve(ctx, tunLn, ingressLn) }()
	st.addr = ingressLn.Addr().String()

	for _, a := range agents {
		backend := startNamedBackend(t, a.name)
		agentLog, _, _ := obs.NewLogger("error", "text", io.Discard)
		ag, err := agent.New(&config.AgentConfig{
			Edge:      config.EdgeRef{Address: tunLn.Addr().String(), CA: caPath, Cert: certPaths[a.cert][0], Key: certPaths[a.cert][1]},
			Routes:    []config.AgentRoute{{Host: "*", Service: backend.Addr().String()}},
			Reconnect: config.ReconnectConfig{MinBackoff: config.Duration(10 * time.Millisecond), MaxBackoff: config.Duration(100 * time.Millisecond)},
			Drain:     config.Duration(5 * time.Second), // as a loaded config always has one (default 15s)
		}, agentLog, obs.NewState("agent"))
		if err != nil {
			t.Fatal(err)
		}
		actx, acancel := context.WithCancel(ctx)
		st.stop[a.name] = acancel
		go func() { _ = ag.Run(actx) }()
	}
	waitSessions(t, st.edge, len(agents))
	return st
}

func waitSessions(t *testing.T, s *obs.State, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Snapshot().Agents) != n {
		if time.Now().After(deadline) {
			t.Fatalf("agent sessions = %d, want %d", len(s.Snapshot().Agents), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// get sends one request and returns the backend name that answered ("" on error).
func get(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Sprintf("status %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestEndToEndRoundRobinAcrossCertificates(t *testing.T) {
	st := buildLBStack(t, []lbAgent{{"one", "cert-a"}, {"two", "cert-b"}}, func(fp map[string]string) config.EdgeRoute {
		return config.EdgeRoute{Host: "*", AgentFingerprints: []string{fp["cert-a"], fp["cert-b"]}, Balance: config.BalanceRoundRobin}
	})
	counts := map[string]int{}
	for i := 0; i < 20; i++ {
		counts[get(t, st.addr)]++
	}
	if counts["one"] != 10 || counts["two"] != 10 {
		t.Fatalf("round robin across two agents: %v", counts)
	}
}

func TestEndToEndSharedCertificate(t *testing.T) {
	st := buildLBStack(t, []lbAgent{{"one", "shared"}, {"two", "shared"}}, func(fp map[string]string) config.EdgeRoute {
		return config.EdgeRoute{Host: "*", AgentFingerprint: fp["shared"], AllowSharedCert: true, Balance: config.BalanceRoundRobin}
	})
	counts := map[string]int{}
	for i := 0; i < 20; i++ {
		counts[get(t, st.addr)]++
	}
	if counts["one"] != 10 || counts["two"] != 10 {
		t.Fatalf("two agents sharing one certificate: %v", counts)
	}
}

// Stopping one agent loses no requests: until the edge has taken it out of
// the pool it may still serve, and from then on the other agent serves all.
func TestEndToEndFailover(t *testing.T) {
	st := buildLBStack(t, []lbAgent{{"one", "cert-a"}, {"two", "cert-b"}}, func(fp map[string]string) config.EdgeRoute {
		return config.EdgeRoute{Host: "*", AgentFingerprints: []string{fp["cert-a"], fp["cert-b"]}}
	})
	st.stop["one"]()
	inPool := func() bool {
		for _, a := range st.edge.Snapshot().Agents {
			if a.Fingerprint == st.certFP["cert-a"] && !a.Draining {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; inPool(); i++ {
		if got := get(t, st.addr); got != "one" && got != "two" {
			t.Fatalf("request %d while agent one stops: %q", i, got)
		}
		if time.Now().After(deadline) {
			t.Fatal("the edge never took the stopping agent out of its pool")
		}
	}
	for i := 0; i < 20; i++ {
		if got := get(t, st.addr); got != "two" {
			t.Fatalf("request %d after agent one left the pool: %q", i, got)
		}
	}
}

// least_conn sends new requests to the agent with fewer open streams.
func TestEndToEndLeastConn(t *testing.T) {
	st := buildLBStack(t, []lbAgent{{"one", "cert-a"}, {"two", "cert-b"}}, func(fp map[string]string) config.EdgeRoute {
		return config.EdgeRoute{Host: "*", AgentFingerprints: []string{fp["cert-a"], fp["cert-b"]}}
	})
	// Hold a WebSocket open on one agent.
	ws, err := net.Dial("tcp", st.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_, _ = io.WriteString(ws, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(ws), nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	busy := resp.Header.Get("X-Backend")
	for i := 0; i < 10; i++ {
		if got := get(t, st.addr); got == busy || got == "" {
			t.Fatalf("request %d went to the busy agent %q (got %q)", i, busy, got)
		}
	}
}

// Stopping an agent gracefully while requests flow loses none: it asks the
// edge to retire it, serves what was already on its way, then drains.
func TestEndToEndGracefulStopLosesNothing(t *testing.T) {
	st := buildLBStack(t, []lbAgent{{"one", "cert-a"}, {"two", "cert-b"}}, func(fp map[string]string) config.EdgeRoute {
		return config.EdgeRoute{Host: "*", AgentFingerprints: []string{fp["cert-a"], fp["cert-b"]}, Balance: config.BalanceRoundRobin}
	})
	// Warm up so both agents have seen the edge's drain support.
	for i := 0; i < 4; i++ {
		get(t, st.addr)
	}
	const workers, perWorker = 8, 40
	bad := make(chan string, workers*perWorker)
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perWorker; i++ {
				if got := get(t, st.addr); got != "one" && got != "two" {
					bad <- got
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	st.stop["one"]()
	for w := 0; w < workers; w++ {
		<-done
	}
	close(bad)
	var failures []string
	for b := range bad {
		failures = append(failures, b)
	}
	if len(failures) > 0 {
		t.Fatalf("%d of %d requests failed during a graceful stop: %v", len(failures), workers*perWorker, failures)
	}
}
