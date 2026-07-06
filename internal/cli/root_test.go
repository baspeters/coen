package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestRunPrintsErrorAndReturnsNonZero(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"install", "bogus"}) // invalid role -> RunE error
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	code := run(root, &buf)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "error:") {
		t.Fatalf("expected an error message, got %q", buf.String())
	}
}

func TestRunSucceedsSilently(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"version"})
	var errbuf bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&errbuf)
	if code := run(root, &errbuf); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if strings.Contains(errbuf.String(), "error:") {
		t.Fatalf("unexpected error output: %q", errbuf.String())
	}
}
