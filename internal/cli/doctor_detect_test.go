package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorAutoDetectNoDaemon(t *testing.T) {
	old := enumerate
	t.Cleanup(func() { enumerate = old })
	enumerate = func() ([]daemon, error) { return nil, nil }

	out, err := runCLI(t, "doctor")
	if err == nil || !strings.Contains(err.Error()+out, "no running coen daemon") {
		t.Fatalf("want a no-daemon auto-detect error, got %v / %q", err, out)
	}
}

// TestDoctorAutoDetectRunsChecks confirms `coen doctor` with no --role detects
// the role from the running daemon and runs that role's checks (they fail here
// on the placeholder PKI paths, which is fine — it proves detection ran).
func TestDoctorAutoDetectRunsChecks(t *testing.T) {
	old := enumerate
	t.Cleanup(func() { enumerate = old })
	cfg := filepath.Join(t.TempDir(), "agent.yaml")
	body := "edge:\n  address: 127.0.0.1:1\n  ca: /a\n  cert: /b\n  key: /c\n" +
		"routes:\n  - host: app.example.com\n    service: 127.0.0.1:2\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	enumerate = func() ([]daemon, error) { return []daemon{{role: "agent", config: cfg}}, nil }

	out, _ := runCLI(t, "doctor", "--json=false")
	if !strings.Contains(out, "pki: ca") {
		t.Fatalf("expected agent checks to run via the auto-detected role, got: %s", out)
	}
}
