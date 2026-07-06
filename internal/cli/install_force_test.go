package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallPreservesExistingUnit(t *testing.T) {
	pinGOOS(t, "linux")
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err != nil {
		t.Fatalf("install: %v", err)
	}
	unitPath := filepath.Join(unitDir, "coen-edge.service")

	marker := []byte("# customized-by-operator\n")
	if err := os.WriteFile(unitPath, marker, 0o644); err != nil {
		t.Fatal(err)
	}

	// A second install without --force must preserve the operator's unit.
	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if got, _ := os.ReadFile(unitPath); !bytes.Equal(got, marker) {
		t.Fatalf("unit should be preserved without --force, got %q", got)
	}

	// With --force it is replaced.
	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir, "--force"); err != nil {
		t.Fatalf("force install: %v", err)
	}
	if got, _ := os.ReadFile(unitPath); bytes.Equal(got, marker) {
		t.Fatal("unit should be overwritten with --force")
	}
}
