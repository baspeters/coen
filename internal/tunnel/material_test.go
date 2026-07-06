package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baspeters/coen/internal/pki"
)

func TestLoadMaterial(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "x.crt")
	keyPath := filepath.Join(dir, "x.key")
	_ = os.WriteFile(caPath, ca.CertPEM(), 0o600)
	cPEM, kPEM, _ := ca.IssueServer("127.0.0.1")
	_ = os.WriteFile(certPath, cPEM, 0o600)
	_ = os.WriteFile(keyPath, kPEM, 0o600)

	pool, cert, err := LoadMaterial(caPath, certPath, keyPath, "edge cert")
	if err != nil {
		t.Fatalf("LoadMaterial: %v", err)
	}
	if pool == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected a non-empty pool and certificate")
	}

	if _, _, err := LoadMaterial(filepath.Join(dir, "nope"), certPath, keyPath, "edge cert"); err == nil || !strings.Contains(err.Error(), "read ca") {
		t.Fatalf("missing ca: got %v, want error containing 'read ca'", err)
	}
	if _, _, err := LoadMaterial(caPath, caPath, keyPath, "client cert"); err == nil || !strings.Contains(err.Error(), "load client cert") {
		t.Fatalf("bad keypair: got %v, want error containing 'load client cert'", err)
	}
}
