package cli

import (
	"bytes"
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

func TestInstallAgent(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if _, err := runCLI(t, "install", "agent", "--unit-dir", unitDir, "--config-dir", configDir, "--bin", "/usr/local/bin/coen"); err != nil {
		t.Fatalf("install: %v", err)
	}
	unit, err := os.ReadFile(filepath.Join(unitDir, "coen-agent.service"))
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	wantExec := "ExecStart=/usr/local/bin/coen agent --config " + filepath.Join(configDir, "agent.yaml")
	if !strings.Contains(string(unit), wantExec) {
		t.Fatalf("unit missing %q:\n%s", wantExec, unit)
	}
	if strings.Contains(string(unit), "AmbientCapabilities") {
		t.Fatal("agent unit should not grant any AmbientCapabilities (it doesn't bind privileged ports)")
	}
	if _, err := os.Stat(filepath.Join(configDir, "agent.yaml")); err != nil {
		t.Fatalf("example config not written: %v", err)
	}
}

func TestInstallRejectsBadRole(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	out, err := runCLI(t, "install", "bogus", "--unit-dir", unitDir, "--config-dir", configDir)
	if err == nil {
		t.Fatal("expected error for bad role")
	}
	if !strings.Contains(err.Error()+out, "role") {
		t.Fatalf("expected a role error, got %q / %q", err, out)
	}
}

// TestInstallPreservesExistingConfig covers the "skip" side of install's
// os.Stat(configPath)/os.IsNotExist branch: running install a second time
// against a --config-dir that already has a config must not overwrite it.
func TestInstallPreservesExistingConfig(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err != nil {
		t.Fatalf("install: %v", err)
	}
	configPath := filepath.Join(configDir, "edge.yaml")

	marker := []byte("# customized-by-operator\n")
	if err := os.WriteFile(configPath, marker, 0o640); err != nil {
		t.Fatalf("overwrite config with marker: %v", err)
	}

	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err != nil {
		t.Fatalf("second install: %v", err)
	}

	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(got, marker) {
		t.Fatalf("expected existing config to be preserved, got %q", got)
	}
}

// TestInstallFailsWhenUnitDirIsFile covers the os.MkdirAll(unitDir, ...)
// error branch: --unit-dir names a path that can't be created as a
// directory because a regular file already sits there.
func TestInstallFailsWhenUnitDirIsFile(t *testing.T) {
	parent := t.TempDir()
	unitDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(unitDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	configDir := t.TempDir()

	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err == nil {
		t.Fatal("expected error when --unit-dir cannot be created")
	}
}

// TestInstallFailsWhenUnitPathIsDirectory covers the os.Create(unitPath)
// error branch: the unit file's target path already exists as a directory.
func TestInstallFailsWhenUnitPathIsDirectory(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(unitDir, "coen-edge.service"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err == nil {
		t.Fatal("expected error when the unit file path is already a directory")
	}
}

// TestInstallFailsWhenConfigDirIsFile covers the os.MkdirAll(configDir, ...)
// error branch, analogous to TestInstallFailsWhenUnitDirIsFile.
func TestInstallFailsWhenConfigDirIsFile(t *testing.T) {
	unitDir := t.TempDir()
	parent := t.TempDir()
	configDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(configDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err == nil {
		t.Fatal("expected error when --config-dir cannot be created")
	}
}

// TestInstallFailsWhenConfigDirNotWritable covers the os.WriteFile(configPath, ...)
// error branch: config-dir exists (so MkdirAll is a no-op) but has no write
// permission, so writing the example config fails. Runners execute as
// non-root, so a 0500 directory reliably blocks new-file creation here.
func TestInstallFailsWhenConfigDirNotWritable(t *testing.T) {
	unitDir := t.TempDir()
	configDir := t.TempDir()
	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := runCLI(t, "install", "edge", "--unit-dir", unitDir, "--config-dir", configDir); err == nil {
		t.Fatal("expected error when --config-dir is not writable")
	}
}
