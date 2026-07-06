package pki

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestValidateFingerprint(t *testing.T) {
	valid := "SHA256:" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if err := ValidateFingerprint(valid); err != nil {
		t.Fatalf("valid fingerprint rejected: %v", err)
	}
	bad := []string{
		"",
		"AA",
		"nope",
		"sha256:" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)), // wrong case prefix
		"SHA256:not@@base64",
		"SHA256:" + base64.StdEncoding.EncodeToString(make([]byte, 31)), // wrong length
	}
	for _, s := range bad {
		if err := ValidateFingerprint(s); err == nil {
			t.Fatalf("expected an error for %q", s)
		}
	}
}

func TestLoadCARejectsNonCACert(t *testing.T) {
	ca, err := CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := ca.IssueServer("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(leafCert, leafKey); err == nil {
		t.Fatal("expected LoadCA to reject a non-CA (leaf) certificate")
	}
}
