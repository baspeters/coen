package cli

import (
	"path/filepath"
	"testing"

	"github.com/baspeters/coen/internal/pki"
)

// writeTestPKI creates a fresh CA plus an edge (server) keypair for host
// 127.0.0.1 under a new temp directory, and returns the directory along with
// the paths to ca.crt, edge.crt and edge.key. It's shared by tests that need
// a config pointing at real, loadable PKI material.
func writeTestPKI(t *testing.T) (dir, caPath, certPath, keyPath string) {
	t.Helper()
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	dir = t.TempDir()
	caPath = filepath.Join(dir, "ca.crt")
	if err := pki.WritePEM(caPath, ca.CertPEM()); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	certPath = filepath.Join(dir, "edge.crt")
	if err := pki.WritePEM(certPath, certPEM); err != nil {
		t.Fatalf("write edge.crt: %v", err)
	}
	keyPath = filepath.Join(dir, "edge.key")
	if err := pki.WritePEM(keyPath, keyPEM); err != nil {
		t.Fatalf("write edge.key: %v", err)
	}
	return dir, caPath, certPath, keyPath
}
