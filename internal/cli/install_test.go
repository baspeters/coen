package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallEdge(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir, "--bin", "/usr/local/bin/coen"); err != nil {
		t.Fatalf("install: %v", err)
	}
	unit, err := os.ReadFile(filepath.Join(unitDir, "coen-edge.service"))
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	wantExec := "ExecStart=/usr/local/bin/coen edge --config " + filepath.Join(configDir, "edge.yaml")
	if !strings.Contains(string(unit), wantExec) {
		t.Fatalf("unit missing %q:\n%s", wantExec, unit)
	}
	if !strings.Contains(string(unit), "CAP_NET_BIND_SERVICE") {
		t.Fatal("edge unit should grant CAP_NET_BIND_SERVICE")
	}
	if _, err := os.Stat(filepath.Join(configDir, "edge.yaml")); err != nil {
		t.Fatalf("example config not written: %v", err)
	}
}
