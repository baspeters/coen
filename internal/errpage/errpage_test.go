package errpage

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func TestRenderContainsAllParts(t *testing.T) {
	html := Render(502, "Bad Gateway", "Backend unreachable", "a1b2c3d4e5f6")
	for _, want := range []string{
		"<!doctype html>",
		"system-ui", // sans-serif stack
		"502",       // HTTP code
		"Bad Gateway",
		"Backend unreachable", // message
		"Coen",                // footer brand
		"a1b2c3d4e5f6",        // correlation id
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered page missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "coen:") {
		t.Errorf("detail should not carry a coen: prefix:\n%s", html)
	}
}

func TestWriteIsValidHTTPResponse(t *testing.T) {
	var sb strings.Builder
	Write(&sb, 404, "Not Found", "No route for host", "deadbeef")
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(sb.String())), nil)
	if err != nil {
		t.Fatalf("not a valid HTTP response: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !resp.Close {
		t.Errorf("expected Connection: close (resp.Close = true)")
	}
	body := make([]byte, resp.ContentLength)
	if _, err := resp.Body.Read(body); err != nil && err.Error() != "EOF" {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "No route for host") {
		t.Errorf("body missing message: %s", body)
	}
}
