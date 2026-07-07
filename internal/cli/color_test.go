package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestColorEnabledNonTTY(t *testing.T) {
	// A bytes.Buffer is not an *os.File, so color must be disabled (this is the
	// path tests and pipes take, keeping output free of escape codes).
	if colorEnabled(&bytes.Buffer{}) {
		t.Fatal("colorEnabled must be false for a non-file writer")
	}
}

func TestColorEnabledNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if colorEnabled(&bytes.Buffer{}) {
		t.Fatal("NO_COLOR must disable color")
	}
}

func TestColorEnabledDumbTerm(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if colorEnabled(&bytes.Buffer{}) {
		t.Fatal("TERM=dumb must disable color")
	}
}

func TestPaint(t *testing.T) {
	if got := paint("✓", ansiGreen, false); got != "✓" {
		t.Fatalf("paint(off) = %q, want plain", got)
	}
	got := paint("✓", ansiGreen, true)
	if !strings.HasPrefix(got, ansiGreen) || !strings.HasSuffix(got, ansiReset) || !strings.Contains(got, "✓") {
		t.Fatalf("paint(on) = %q, want green-wrapped mark", got)
	}
}

func TestAgentIP(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7:4444":  "198.51.100.7",
		"[2001:db8::1]:9000": "2001:db8::1",
		"":                   "unknown",
		"not-an-addr":        "not-an-addr",
	}
	for in, want := range cases {
		if got := agentIP(in); got != want {
			t.Fatalf("agentIP(%q) = %q, want %q", in, got, want)
		}
	}
}
