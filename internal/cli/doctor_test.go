package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baspeters/coen/internal/doctor"
)

func TestDoctorRejectsBadRole(t *testing.T) {
	out, err := runCLI(t, "doctor", "--role", "bogus")
	if err == nil {
		t.Fatal("expected error for bad role")
	}
	if !strings.Contains(err.Error()+out, "role") {
		t.Fatalf("expected a role error, got %q / %q", err, out)
	}
}

func TestDoctorErrorsOnMissingConfig(t *testing.T) {
	if _, err := runCLI(t, "doctor", "--role", "agent", "--config", "/no/such/agent.yaml"); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestCountFailures(t *testing.T) {
	results := []doctor.Result{
		{Name: "a", OK: true},
		{Name: "b", OK: false},
		{Name: "c", OK: false},
		{Name: "d", OK: true},
	}
	if n := countFailures(results); n != 2 {
		t.Fatalf("countFailures = %d, want 2", n)
	}
	if n := countFailures(nil); n != 0 {
		t.Fatalf("countFailures(nil) = %d, want 0", n)
	}
}

// TestDoctorEdgeJSON runs a full, passing edge doctor check (real temp PKI,
// proxied ingress, and ephemeral ports so the bind checks succeed) and
// asserts the --json output decodes as a JSON array of results.
func TestDoctorEdgeJSON(t *testing.T) {
	_, caPath, certPath, keyPath := writeTestPKI(t)
	cfgPath := filepath.Join(t.TempDir(), "edge.yaml")
	cfg := fmt.Sprintf(`
ingress:
  mode: proxied
  listen: "127.0.0.1:0"
tunnel:
  listen: "127.0.0.1:0"
  ca: %s
  cert: %s
  key: %s
routes:
  - host: "*"
    agent_fingerprint: "%s"
`, caPath, certPath, keyPath, "SHA256:"+base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, err := runCLI(t, "doctor", "--role", "edge", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("doctor: %v (output: %s)", err, out)
	}

	var results []doctor.Result
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, out)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("unexpected failing check %q: %s", r.Name, r.Detail)
		}
	}
}

// TestDoctorAgentFailureExitsNonZero points the agent doctor check at PKI
// paths that don't exist, so it fails fast (no network I/O) with several
// failing checks, and asserts the human-readable output marks them with ✗.
func TestDoctorAgentFailureExitsNonZero(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agent.yaml")
	cfg := `
edge:
  address: 127.0.0.1:1
  ca: /no/such/ca.crt
  cert: /no/such/agent.crt
  key: /no/such/agent.key
routes:
  - host: "*"
    service: 127.0.0.1:1
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --json is passed explicitly (even though false is the flag's default)
	// because newDoctorCmd's flag variable is shared across every runCLI
	// call in this process (subcommands are built once via init/register),
	// so a prior --json=true test in this file would otherwise leak here.
	out, err := runCLI(t, "doctor", "--role", "agent", "--config", cfgPath, "--json=false")
	if err == nil {
		t.Fatalf("expected doctor to report failures, got output: %s", out)
	}
	if !strings.Contains(out, "✗") {
		t.Fatalf("expected ✗ marks in output, got %q", out)
	}
	// The checks are introduced by a role/config header.
	if !strings.Contains(out, "coen doctor: agent checks (config: "+cfgPath+")") {
		t.Fatalf("expected a role/config header before the checks, got %q", out)
	}
}
