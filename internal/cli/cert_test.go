package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/baspeters/coen/internal/pki"
)

// runCLI executes the root command with args, capturing combined output.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestCertInitAndIssue(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "init", "--dir", dir); err != nil {
		t.Fatalf("cert init: %v", err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	if _, err := runCLI(t, "cert", "edge", "--dir", dir, "--host", "edge.example.com"); err != nil {
		t.Fatalf("cert edge: %v", err)
	}
	if _, err := runCLI(t, "cert", "agent", "--dir", dir, "--name", "agent-1"); err != nil {
		t.Fatalf("cert agent: %v", err)
	}
	agentPEM, err := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if err != nil {
		t.Fatalf("read agent.crt: %v", err)
	}
	if fp, err := pki.FingerprintPEM(agentPEM); err != nil || fp == "" {
		t.Fatalf("agent cert invalid: %v", err)
	}
	// init must refuse to overwrite an existing CA without --force.
	if _, err := runCLI(t, "cert", "init", "--dir", dir); err == nil {
		t.Fatal("expected init to refuse overwrite")
	}
}
