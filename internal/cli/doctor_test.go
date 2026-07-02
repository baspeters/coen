package cli

import (
	"strings"
	"testing"
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
