package agent

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/obs"
	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
)

func preambleErrors(s *obs.State) int64 {
	return s.Detail().UnroutedFailures.Get(obs.ReasonPreambleError)
}

// A stream that closes before its preamble (as on an edge restart) is routine
// teardown and not counted; a malformed preamble is a protocol fault and is.
func TestHandleStreamPreambleClassification(t *testing.T) {
	st := obs.NewState("agent")
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: st}

	run := func(feed func(c net.Conn)) {
		t.Helper()
		edgeSide, agentSide := net.Pipe()
		done := make(chan struct{})
		go func() { a.handleStream(context.Background(), agentSide, false); close(done) }()
		feed(edgeSide)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("handleStream did not return")
		}
	}

	run(func(c net.Conn) { _ = c.Close() })
	if got := preambleErrors(st); got != 0 {
		t.Fatalf("closed-before-preamble counted as preamble_error (%d)", got)
	}

	run(func(c net.Conn) {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 5)
		_, _ = c.Write(append(hdr[:], []byte("{bad}")...))
		_ = c.Close()
	})
	if got := preambleErrors(st); got != 1 {
		t.Fatalf("malformed preamble: preamble_error = %d, want 1", got)
	}

	// A length prefix promising more bytes than arrive is a framing fault.
	run(func(c net.Conn) {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 100)
		_, _ = c.Write(append(hdr[:], []byte(`{"conn_id":"x"`)...))
		_ = c.Close()
	})
	if got := preambleErrors(st); got != 2 {
		t.Fatalf("truncated preamble: preamble_error = %d, want 2", got)
	}

	// Only the length prefix arrives before the stream closes: truncated too.
	run(func(c net.Conn) {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 40)
		_, _ = c.Write(hdr[:])
		_ = c.Close()
	})
	if got := preambleErrors(st); got != 3 {
		t.Fatalf("length prefix only: preamble_error = %d, want 3", got)
	}
}

// A shutdown signal must not cancel the backend dial of an accepted stream:
// the drain lets it complete, and a healthy backend is not a dial_error.
func TestHandleStreamDialSurvivesShutdownSignal(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err == nil {
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			_ = c.Close()
		}
	}()
	st := obs.NewState("agent")
	a := &Agent{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		state:  st,
		routes: route.Build([]route.Entry[agentRoute]{{Pattern: "*", Value: agentRoute{service: backend.Addr().String(), stats: st.Route("*")}}}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown already signalled when the stream is handled
	edgeSide, agentSide := net.Pipe()
	go a.handleStream(ctx, agentSide, false)
	if err := writePreamble(edgeSide, tunnel.Preamble{ConnID: "c", Host: "app"}); err != nil {
		t.Fatal(err)
	}
	_ = edgeSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, _ := io.ReadAll(edgeSide)
	if string(resp) != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" {
		t.Fatalf("stream was not served after the shutdown signal: %q", resp)
	}
	if got := st.Detail().Routes[0].Failures.Get(obs.ReasonDialError); got != 0 {
		t.Fatalf("dial_error = %d, want 0", got)
	}
}

// With version 2 the agent accepts a stream on arrival, before reading its
// preamble, and the accept byte is the first thing on it, even when the agent
// then answers with an error page.
func TestHandleStreamAcceptsOnArrival(t *testing.T) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: obs.NewState("agent"), routes: route.Build[agentRoute](nil)}
	edgeSide, agentSide := net.Pipe()
	done := make(chan struct{})
	go func() { a.handleStream(context.Background(), agentSide, true); close(done) }()
	if err := tunnel.AwaitAccept(edgeSide, 2*time.Second); err != nil {
		t.Fatalf("no accept byte on arrival: %v", err)
	}
	_ = writePreamble(edgeSide, tunnel.Preamble{ConnID: "c", Host: "nowhere"})
	rest, _ := io.ReadAll(edgeSide)
	<-done
	if !strings.Contains(string(rest), "502") {
		t.Fatalf("the error page must follow the accept byte, got %q", rest)
	}
}
