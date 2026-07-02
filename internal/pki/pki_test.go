package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
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

func TestLoadCAInvalidCertPEM(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	_, err = LoadCA([]byte("not a pem block"), ca.KeyPEM())
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
	if !strings.Contains(err.Error(), "ca cert") {
		t.Fatalf("expected error to mention ca cert, got %v", err)
	}
}

func TestLoadCAInvalidKeyPEM(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	_, err = LoadCA(ca.CertPEM(), []byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
	if !strings.Contains(err.Error(), "no PEM key found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadCANonEd25519Key(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = LoadCA(ca.CertPEM(), rsaKeyPEM)
	if err == nil {
		t.Fatal("expected error for non-Ed25519 key")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadCAInvalidKeyDER(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	// Valid PEM wrapper but garbage DER payload, so pem.Decode succeeds
	// while x509.ParsePKCS8PrivateKey fails.
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not valid der")})

	_, err = LoadCA(ca.CertPEM(), badKeyPEM)
	if err == nil {
		t.Fatal("expected error for undecodable key DER")
	}
	if !strings.Contains(err.Error(), "ca key") {
		t.Fatalf("expected error to mention ca key, got %v", err)
	}
}

func TestFingerprintPEMValid(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	fp, err := FingerprintPEM(ca.CertPEM())
	if err != nil {
		t.Fatalf("FingerprintPEM: %v", err)
	}
	if fp != Fingerprint(ca.Cert) {
		t.Fatalf("FingerprintPEM(%q) = %q, want %q", ca.CertPEM(), fp, Fingerprint(ca.Cert))
	}
}

func TestParseCertPEMInvalid(t *testing.T) {
	_, err := parseCertPEM([]byte("this is definitely not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestFingerprintPEMInvalid(t *testing.T) {
	_, err := FingerprintPEM([]byte("this is definitely not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestCertPoolFromPEMInvalid(t *testing.T) {
	_, err := CertPoolFromPEM([]byte("this is definitely not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestCertPoolFromPEMEmpty(t *testing.T) {
	_, err := CertPoolFromPEM([]byte{})
	if err == nil {
		t.Fatal("expected error for empty CA PEM")
	}
}

func TestIssueServerIPHostYieldsIPSAN(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	certPEM, _, err := ca.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected single IP SAN 127.0.0.1, got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs for an IP host, got %v", cert.DNSNames)
	}
}

func TestIssueServerDNSHostYieldsDNSSAN(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	certPEM, _, err := ca.IssueServer("edge.example.com")
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "edge.example.com" {
		t.Fatalf("expected single DNS SAN edge.example.com, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs for a DNS host, got %v", cert.IPAddresses)
	}
}

func TestIssueClientCertFields(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueClient("agent-1")
	if err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	if cert.Subject.CommonName != "agent-1" {
		t.Fatalf("expected CommonName agent-1, got %q", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("expected ExtKeyUsageClientAuth, got %v", cert.ExtKeyUsage)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("expected issued client key to be PEM encoded")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("issued client key is not valid PKCS8: %v", err)
	}
}

func TestWritePEMRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leaf.pem")
	data := []byte("-----BEGIN CERTIFICATE-----\nfake-data\n-----END CERTIFICATE-----\n")

	if err := WritePEM(path, data); err != nil {
		t.Fatalf("WritePEM: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: got %q want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600, got %v", perm)
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
