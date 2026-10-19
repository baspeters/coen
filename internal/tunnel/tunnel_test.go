package tunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/pki"
	"github.com/hashicorp/yamux"
)

func TestPreambleRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Preamble{ConnID: "abc123", ClientAddr: "203.0.113.7:5555"}
	if err := writePreamble(&buf, in); err != nil {
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

func TestEncodePreambleTooLarge(t *testing.T) {
	big := Preamble{ConnID: "x", ClientAddr: strings.Repeat("a", maxPreamble+100)}
	if b, err := EncodePreamble(big); err == nil || b != nil {
		t.Fatalf("expected an error and no bytes for an oversized preamble, got %d bytes, %v", len(b), err)
	}
}

func TestReadPreambleTruncatedHeader(t *testing.T) {
	// Only one of the two length-prefix bytes is present.
	if _, err := ReadPreamble(bytes.NewReader([]byte{0x00})); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadPreambleTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 10)
	buf.Write(hdr[:])
	buf.WriteString("short") // fewer than the declared 10 bytes
	if _, err := ReadPreamble(&buf); err == nil {
		t.Fatal("expected error for truncated body")
	}
}

func TestReadPreambleLengthExceedsMax(t *testing.T) {
	var buf bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], maxPreamble+1)
	buf.Write(hdr[:])
	if _, err := ReadPreamble(&buf); err == nil {
		t.Fatal("expected error when declared length exceeds max")
	}
}

func TestReadPreambleInvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("not-json-at-all")
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	buf.Write(hdr[:])
	buf.Write(body)
	if _, err := ReadPreamble(&buf); err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
}

func TestServerClientSessionLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverErrc := make(chan error, 1)
	serverMsg := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrc <- err
			return
		}
		sess, err := ServerSession(conn)
		if err != nil {
			serverErrc <- err
			return
		}
		defer func() { _ = sess.Close() }()

		stream, err := sess.AcceptStream()
		if err != nil {
			serverErrc <- err
			return
		}
		defer func() { _ = stream.Close() }()

		got := make([]byte, 5)
		if _, err := io.ReadFull(stream, got); err != nil {
			serverErrc <- err
			return
		}
		serverMsg <- string(got)

		if _, err := stream.Write([]byte("world")); err != nil {
			serverErrc <- err
			return
		}
		serverErrc <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientSess, err := ClientSession(conn)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer func() { _ = clientSess.Close() }()

	stream, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer func() { _ = stream.Close() }()

	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, 5)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "world" {
		t.Fatalf("client got reply %q, want %q", reply, "world")
	}

	select {
	case got := <-serverMsg:
		if got != "hello" {
			t.Fatalf("server got %q, want %q", got, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to receive stream data")
	}

	if err := <-serverErrc; err != nil {
		t.Fatalf("server goroutine error: %v", err)
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

func TestPreambleRoundTripHost(t *testing.T) {
	var buf bytes.Buffer
	in := Preamble{ConnID: "abc", ClientAddr: "1.2.3.4:5", Host: "app.example.com"}
	if err := writePreamble(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadPreamble(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Host != in.Host {
		t.Errorf("Host = %q, want %q", out.Host, in.Host)
	}
}

func TestIsTeardown(t *testing.T) {
	for _, err := range []error{io.EOF, net.ErrClosed, yamux.ErrStreamClosed, yamux.ErrSessionShutdown, yamux.ErrConnectionReset, fmt.Errorf("read: %w", io.EOF)} {
		if !IsTeardown(err) {
			t.Errorf("IsTeardown(%v) = false, want true", err)
		}
	}
	for _, err := range []error{io.ErrUnexpectedEOF, syscall.ECONNRESET, errors.New("preamble too large: 9999 bytes"), os.ErrDeadlineExceeded, &json.SyntaxError{}} {
		if IsTeardown(err) {
			t.Errorf("IsTeardown(%v) = true, want false", err)
		}
	}
}

func TestReadPreambleLengthPrefixOnlyIsTruncated(t *testing.T) {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 10)
	if _, err := ReadPreamble(bytes.NewReader(hdr[:])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadPreamble(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("an empty stream must stay io.EOF (teardown), got %v", err)
	}
}

// The edge negotiates coen/2 with a client that asks for it, and still accepts
// a client that asks for something else (falling back to version 1).
func TestALPNNegotiationAndFallback(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	sc, sk, _ := ca.IssueServer("127.0.0.1")
	cc, ck, _ := ca.IssueClient("a")
	srvCert, _ := tls.X509KeyPair(sc, sk)
	cliCert, _ := tls.X509KeyPair(cc, ck)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerTLSConfig(pool, srvCert))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	for _, offer := range [][]string{{ALPNv2}, {"coen/3"}, nil} {
		cfg := ClientTLSConfig(pool, cliCert, "127.0.0.1")
		cfg.NextProtos = offer
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatalf("client offering %v could not connect: %v", offer, err)
		}
		got := c.ConnectionState().NegotiatedProtocol
		_ = c.Close()
		want := ""
		if len(offer) == 1 && offer[0] == ALPNv2 {
			want = ALPNv2
		}
		if got != want {
			t.Fatalf("offer %v negotiated %q, want %q", offer, got, want)
		}
	}
}

// writePreamble encodes p and writes it to w, for tests.
func writePreamble(w io.Writer, p Preamble) error {
	b, err := EncodePreamble(p)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// EncodePreamble returns one whole frame (length prefix and body), so the
// edge sends it in a single Write and an agent never sees a lone prefix.
func TestEncodePreambleIsOneFrame(t *testing.T) {
	want := Preamble{ConnID: "c", Host: "h", ClientAddr: "1.2.3.4:5"}
	b, err := EncodePreamble(want)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(b)
	got, err := ReadPreamble(r)
	if err != nil || got.ConnID != want.ConnID || got.Host != want.Host || got.ClientAddr != want.ClientAddr {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	if r.Len() != 0 {
		t.Fatalf("%d bytes left over after the frame", r.Len())
	}
}
