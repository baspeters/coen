package metrics

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

func TestHandler(t *testing.T) {
	s := obs.NewState("edge")
	s.Route("app.example.com")
	h := Handler(s, "dev")

	cases := []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/metrics", 200},
		{http.MethodHead, "/metrics", 200},
		{http.MethodPost, "/metrics", 405},
		{http.MethodGet, "/", 404},
		{http.MethodGet, "/metrics/extra", 404},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, rec.Code, c.code)
		}
		if c.code == 200 && rec.Header().Get("Content-Type") != ContentType {
			t.Errorf("%s %s Content-Type = %q", c.method, c.path, rec.Header().Get("Content-Type"))
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `coen_streams_total{route="app.example.com"} 0`) {
		t.Fatalf("unexpected body:\n%s", rec.Body.String())
	}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestServeAndShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, Handler(obs.NewState("agent"), "dev"), discard()) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "coen_tunnel_up 0") {
		t.Fatalf("status %d body:\n%s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v on clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
}

func TestServeReturnsListenerError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Serve on a closed listener fails immediately
	if err := Serve(context.Background(), ln, http.NotFoundHandler(), discard()); err == nil {
		t.Fatal("expected an error from a closed listener")
	}
}
