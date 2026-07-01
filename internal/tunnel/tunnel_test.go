package tunnel

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestPreambleRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Preamble{ConnID: "abc123", ClientAddr: "203.0.113.7:5555"}
	if err := WritePreamble(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Append trailing payload to prove ReadPreamble stops at the boundary.
	buf.WriteString("RAWBYTES")
	out, err := ReadPreamble(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if rest := buf.String(); rest != "RAWBYTES" {
		t.Fatalf("preamble consumed payload; rest=%q", rest)
	}
}

func TestServerTLSConfigRequiresClientCert(t *testing.T) {
	cfg := ServerTLSConfig(nil, tls.Certificate{})
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("server must require+verify client cert")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("tunnel must enforce TLS 1.3")
	}
}

func TestClientTLSConfigSetsServerName(t *testing.T) {
	cfg := ClientTLSConfig(nil, tls.Certificate{}, "edge.example.com")
	if cfg.ServerName != "edge.example.com" || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("bad client config: %+v", cfg)
	}
}
