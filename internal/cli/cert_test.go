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

func TestCertEdgeRequiresHost(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "edge", "--dir", dir); err == nil {
		t.Fatal("expected error when --host is omitted")
	}
}

func TestCertAgentRequiresName(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "agent", "--dir", dir); err == nil {
		t.Fatal("expected error when --name is omitted")
	}
}

// TestCertEdgeFailsWithoutCA exercises loadCADir's ca.crt-read error as
// surfaced through newCertEdgeCmd, against a --dir that has no CA at all.
func TestCertEdgeFailsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "edge", "--dir", dir, "--host", "edge.example.com"); err == nil {
		t.Fatal("expected error when the CA directory has no ca.crt")
	}
}

// TestCertAgentFailsWithoutCA is the newCertAgentCmd counterpart of
// TestCertEdgeFailsWithoutCA.
func TestCertAgentFailsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "agent", "--dir", dir, "--name", "agent-1"); err == nil {
		t.Fatal("expected error when the CA directory has no ca.crt")
	}
}

// TestCertEdgeFailsWithCACertButNoKey covers loadCADir's other read branch:
// ca.crt is present and valid, but ca.key is missing.
func TestCertEdgeFailsWithCACertButNoKey(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.WritePEM(filepath.Join(dir, "ca.crt"), ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "cert", "edge", "--dir", dir, "--host", "edge.example.com"); err == nil {
		t.Fatal("expected error when ca.key is missing")
	}
}

// TestCertEdgeWriteLeafFailsOnReadOnlyDir drives writeLeaf's WritePEM error
// path: the CA loads and issuance succeeds, but the directory has no write
// permission, so writing edge.crt fails. Runners execute as non-root, so a
// 0500 directory reliably blocks new-file creation here.
func TestCertEdgeWriteLeafFailsOnReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "init", "--dir", dir); err != nil {
		t.Fatalf("cert init: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := runCLI(t, "cert", "edge", "--dir", dir, "--host", "edge.example.com"); err == nil {
		t.Fatal("expected error writing the leaf cert into a read-only directory")
	}
}

// TestCertInitForceOverwritesCA covers the --force overwrite path: a second
// init against the same --dir succeeds and replaces the CA material.
func TestCertInitForceOverwritesCA(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCLI(t, "cert", "init", "--dir", dir); err != nil {
		t.Fatalf("cert init: %v", err)
	}
	firstPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read first ca.crt: %v", err)
	}

	if _, err := runCLI(t, "cert", "init", "--dir", dir, "--force"); err != nil {
		t.Fatalf("cert init --force: %v", err)
	}
	secondPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read second ca.crt: %v", err)
	}
	if bytes.Equal(firstPEM, secondPEM) {
		t.Fatal("expected --force to generate a fresh CA, but ca.crt is unchanged")
	}
}

// TestCertInitFailsWhenDirParentIsFile covers newCertInitCmd's
// os.MkdirAll(dir, ...) error branch: a path component of --dir is a
// regular file, so it can never be created as a directory.
func TestCertInitFailsWhenDirParentIsFile(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "pki")
	if _, err := runCLI(t, "cert", "init", "--dir", dir); err == nil {
		t.Fatal("expected error when a --dir path component is a regular file")
	}
}
