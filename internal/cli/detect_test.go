package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDaemon(t *testing.T) {
	cases := []struct {
		argv         []string
		ok           bool
		role, config string
	}{
		{[]string{"/usr/local/bin/coen", "edge", "--config", "/x/edge.yaml"}, true, "edge", "/x/edge.yaml"},
		{[]string{"coen", "agent"}, true, "agent", "/etc/coen/agent.yaml"},
		{[]string{"coen", "agent", "--config=/y/a.yaml"}, true, "agent", "/y/a.yaml"},
		{[]string{"coen", "doctor"}, false, "", ""},       // not a daemon subcommand
		{[]string{"grep", "coen", "edge"}, false, "", ""}, // argv0 is not coen
		{[]string{"coen"}, false, "", ""},                 // too short
		{[]string{"/opt/coen", "status", "--json"}, false, "", ""},
	}
	for _, c := range cases {
		d, ok := parseDaemon(42, c.argv)
		if ok != c.ok {
			t.Fatalf("argv %v: ok=%v want %v", c.argv, ok, c.ok)
		}
		if ok && (d.role != c.role || d.config != c.config) {
			t.Fatalf("argv %v: got role=%q config=%q", c.argv, d.role, d.config)
		}
	}
}

func TestDetectRole(t *testing.T) {
	old := enumerate
	t.Cleanup(func() { enumerate = old })

	enumerate = func() ([]daemon, error) {
		return []daemon{{pid: 1, role: "agent", config: "/etc/coen/agent.yaml"}}, nil
	}
	if r, c, err := detectRole(); err != nil || r != "agent" || c != "/etc/coen/agent.yaml" {
		t.Fatalf("single agent: r=%q c=%q err=%v", r, c, err)
	}

	enumerate = func() ([]daemon, error) { return nil, nil }
	if _, _, err := detectRole(); !errors.Is(err, errNoDaemon) {
		t.Fatalf("none running: want errNoDaemon, got %v", err)
	}

	enumerate = func() ([]daemon, error) {
		return []daemon{{role: "edge"}, {role: "agent"}}, nil
	}
	if _, _, err := detectRole(); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("both running: want ambiguity error, got %v", err)
	}
}

// TestEnumerateDaemonsRuns exercises the real OS enumerator on the test host
// (which has no coen daemon), so it must return without error and find none.
func TestEnumerateDaemonsRuns(t *testing.T) {
	ds, err := enumerateDaemons()
	if err != nil {
		t.Fatalf("enumerateDaemons: %v", err)
	}
	for _, d := range ds {
		if d.role != "edge" && d.role != "agent" {
			t.Fatalf("unexpected role %q", d.role)
		}
	}
}
