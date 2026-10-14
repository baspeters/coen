package config

import (
	"strings"
	"testing"
)

func TestEdgeRouteAgentsValidation(t *testing.T) {
	cases := []struct {
		name  string
		route EdgeRoute
		err   string
	}{
		{"single", EdgeRoute{Host: "a", AgentFingerprint: "A"}, ""},
		{"list", EdgeRoute{Host: "a", AgentFingerprints: []string{"A", "B"}}, ""},
		{"list round robin", EdgeRoute{Host: "a", AgentFingerprints: []string{"A", "B"}, Balance: "round_robin"}, ""},
		{"shared", EdgeRoute{Host: "a", AgentFingerprint: "A", AllowSharedCert: true}, ""},
		{"both", EdgeRoute{Host: "a", AgentFingerprint: "A", AgentFingerprints: []string{"B"}}, "not both"},
		{"neither", EdgeRoute{Host: "a"}, "is required"},
		{"empty entry", EdgeRoute{Host: "a", AgentFingerprints: []string{"A", ""}}, "empty entry"},
		{"repeated", EdgeRoute{Host: "a", AgentFingerprints: []string{"A", "A"}}, "twice"},
		{"bad balance", EdgeRoute{Host: "a", AgentFingerprint: "A", Balance: "random"}, "balance must be"},
	}
	for _, c := range cases {
		e := validEdgeConfig()
		e.Routes = []EdgeRoute{c.route}
		err := e.Validate()
		if c.err == "" && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.err, err)
		}
	}
}

// Sharing is per certificate: a fingerprint must be shared on every route that
// names it, or on none.
func TestSharedCertMustBeConsistentAcrossRoutes(t *testing.T) {
	e := validEdgeConfig()
	e.Routes = []EdgeRoute{
		{Host: "a.example.com", AgentFingerprints: []string{"A", "B"}, AllowSharedCert: true},
		{Host: "b.example.com", AgentFingerprint: "B"},
	}
	err := e.Validate()
	if err == nil || !strings.Contains(err.Error(), "allow_shared_cert on route \"a.example.com\" but not on route \"b.example.com\"") {
		t.Fatalf("want an inconsistency error, got %v", err)
	}
	e.Routes[1].AllowSharedCert = true
	if err := e.Validate(); err != nil {
		t.Fatalf("consistent sharing must pass: %v", err)
	}
	shared := e.SharedFingerprints()
	if !shared["A"] || !shared["B"] || len(shared) != 2 {
		t.Fatalf("SharedFingerprints = %v", shared)
	}
	allowed := e.AllowedFingerprints()
	if !allowed["A"] || !allowed["B"] {
		t.Fatalf("AllowedFingerprints = %v", allowed)
	}
}

func TestEdgeRouteHelpers(t *testing.T) {
	if got := (EdgeRoute{AgentFingerprint: "A"}).Fingerprints(); len(got) != 1 || got[0] != "A" {
		t.Fatalf("Fingerprints(single) = %v", got)
	}
	if got := (EdgeRoute{AgentFingerprints: []string{"A", "B"}}).Fingerprints(); len(got) != 2 {
		t.Fatalf("Fingerprints(list) = %v", got)
	}
	if (EdgeRoute{}).BalanceMode() != BalanceLeastConn || (EdgeRoute{Balance: BalanceRoundRobin}).BalanceMode() != BalanceRoundRobin {
		t.Fatal("BalanceMode defaults to least_conn and keeps an explicit choice")
	}
}

func TestLoadEdgeParsesBalancing(t *testing.T) {
	p := writeTemp(t, "edge.yaml", `
ingress: { mode: proxied, listen: "127.0.0.1:8000" }
tunnel: { listen: ":2636", ca: /a, cert: /b, key: /c }
routes:
  - host: app.example.com
    agent_fingerprints: ["SHA256:aaa", "SHA256:bbb"]
    balance: round_robin
    allow_shared_cert: true
`)
	c, err := LoadEdge(p)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Routes[0]
	if len(r.Fingerprints()) != 2 || r.BalanceMode() != BalanceRoundRobin || !r.AllowSharedCert {
		t.Fatalf("parsed route = %+v", r)
	}
}

// With several conflicting fingerprints the error is always about the same one:
// the first in config order.
func TestSharedConflictErrorIsStable(t *testing.T) {
	e := validEdgeConfig()
	e.Routes = []EdgeRoute{
		{Host: "a.example.com", AgentFingerprints: []string{"Z", "B", "M"}, AllowSharedCert: true},
		{Host: "b.example.com", AgentFingerprints: []string{"Z", "B", "M"}},
	}
	first := e.Validate()
	for i := 0; i < 20; i++ {
		if err := e.Validate(); err == nil || err.Error() != first.Error() || !strings.Contains(err.Error(), "fingerprint Z ") {
			t.Fatalf("unstable or unexpected error: %v (first: %v)", err, first)
		}
	}
}
