package edge

import (
	"errors"
	"strings"
	"testing"
)

var errTest = errors.New("boom")

func TestReadRequestHead(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: App.Example.com:443\r\nUser-Agent: t\r\n\r\nBODY"
	head, host, err := readRequestHead(strings.NewReader(raw), 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	if host != "app.example.com" {
		t.Errorf("host = %q, want app.example.com", host)
	}
	if !strings.Contains(string(head), "\r\n\r\n") {
		t.Errorf("head does not include terminator: %q", head)
	}
}

func TestReadRequestHeadNoHost(t *testing.T) {
	raw := "GET / HTTP/1.0\r\n\r\n"
	if _, _, err := readRequestHead(strings.NewReader(raw), 1<<16); err == nil {
		t.Fatal("expected error for missing Host")
	}
}

func TestReadRequestHeadTooLarge(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("y", 200) + "\r\n\r\n"
	if _, _, err := readRequestHead(strings.NewReader(raw), 64); err == nil {
		t.Fatal("expected error for oversized head")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestReadRequestHeadReadError(t *testing.T) {
	if _, _, err := readRequestHead(errReader{err: errTest}, 1<<16); err == nil {
		t.Fatal("expected error from a failing reader")
	}
}

func TestReadRequestHeadIncomplete(t *testing.T) {
	// EOF arrives before the header terminator.
	if _, _, err := readRequestHead(strings.NewReader("GET / HTTP/1.1\r\nHost: a"), 1<<16); err == nil {
		t.Fatal("expected error for an incomplete request head")
	}
}
