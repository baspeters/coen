package cli

import "testing"

func TestEdgeCmdErrorsOnMissingConfig(t *testing.T) {
	if _, err := runCLI(t, "edge", "--config", "/no/such/edge.yaml"); err == nil {
		t.Fatal("expected error for missing edge config")
	}
}

func TestAgentCmdErrorsOnMissingConfig(t *testing.T) {
	if _, err := runCLI(t, "agent", "--config", "/no/such/agent.yaml"); err == nil {
		t.Fatal("expected error for missing agent config")
	}
}
