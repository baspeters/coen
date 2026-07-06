package edge

import "testing"

func TestParseHostRejectsMultipleHostHeaders(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com")
	if _, err := parseHost(head); err == nil {
		t.Fatal("expected an error for multiple Host headers")
	}
	if h, err := parseHost([]byte("GET / HTTP/1.1\r\nHost: a.example.com")); err != nil || h != "a.example.com" {
		t.Fatalf("single Host: got %q, %v", h, err)
	}
}
