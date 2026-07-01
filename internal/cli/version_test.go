package cli

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, want := out.String(), "coen dev\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
