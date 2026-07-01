package pki

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestCreateCAAndIssue(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	pool, err := CertPoolFromPEM(ca.CertPEM())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}

	// Server cert must verify against the CA for ServerAuth.
	sCertPEM, _, err := ca.IssueServer("edge.example.com")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	sCert := parseLeaf(t, sCertPEM)
	if _, err := sCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSName: "edge.example.com"}); err != nil {
		t.Fatalf("server verify: %v", err)
	}

	// Client cert must verify for ClientAuth.
	cCertPEM, _, err := ca.IssueClient("agent-1")
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	cCert := parseLeaf(t, cCertPEM)
	if _, err := cCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client verify: %v", err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	ca, _ := CreateCA()
	fp := Fingerprint(ca.Cert)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 20 {
		t.Fatalf("unexpected fingerprint %q", fp)
	}
}

func TestLoadCARoundTrip(t *testing.T) {
	ca, _ := CreateCA()
	loaded, err := LoadCA(ca.CertPEM(), ca.KeyPEM())
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if Fingerprint(loaded.Cert) != Fingerprint(ca.Cert) {
		t.Fatal("loaded CA fingerprint differs")
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	pool, err := CertPoolFromPEM(certPEM)
	_ = pool
	if err != nil {
		t.Fatalf("leaf pem: %v", err)
	}
	// Re-parse via pem for the *x509.Certificate value.
	c, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}
