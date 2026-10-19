//go:build unix

package cli

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
)

// handoffPipes sets up the environment a replacement is started with, on
// this process: it returns the predecessor's ends (go-ahead to write,
// "prepared" to read).
func handoffPipes(t *testing.T) (goW *os.File, prepR *os.File) {
	t.Helper()
	goR, goW, _ := os.Pipe()
	prepR, prepW, _ := os.Pipe()
	// FromEnv wraps raw descriptors; give it its own copies, so its closes do
	// not touch the test's files.
	g, err := syscall.Dup(int(goR.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	p, err := syscall.Dup(int(prepW.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = goR.Close()
	_ = prepW.Close()
	t.Setenv("COEN_HANDOFF_FDS", fmt.Sprintf("%d,%d", g, p))
	t.Cleanup(func() { _ = goW.Close(); _ = prepR.Close() })
	return goW, prepR
}

func TestAwaitTurn(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	_ = os.Unsetenv("COEN_HANDOFF_FDS")
	if err := awaitTurn(log); err != nil || buf.Len() != 0 {
		t.Fatalf("started normally: %v %q", err, buf.String())
	}

	goW, prepR := handoffPipes(t)
	if _, err := goW.Write([]byte{'G'}); err != nil {
		t.Fatal(err)
	}
	if err := awaitTurn(log); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(prepR)
	if string(b) != "P" || !strings.Contains(buf.String(), "reload.taking_over") {
		t.Fatalf("reported %q, log %q", b, buf.String())
	}

	// The process being replaced went away without a go-ahead: start anyway.
	buf.Reset()
	goW, _ = handoffPipes(t)
	_ = goW.Close()
	if err := awaitTurn(log); err != nil || !strings.Contains(buf.String(), "reload.no_go_ahead") {
		t.Fatalf("%v %q", err, buf.String())
	}

	t.Setenv("COEN_HANDOFF_FDS", "bad")
	if err := awaitTurn(log); err == nil {
		t.Fatal("a broken handoff environment must fail")
	}
}

// The process being replaced is gone before this one could report.
func TestAwaitTurnCannotReport(t *testing.T) {
	_, prepR := handoffPipes(t)
	_ = prepR.Close() // nobody reads the report: writing it fails
	if err := awaitTurn(slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), "report to the process being replaced") {
		t.Fatalf("got %v", err)
	}
}
