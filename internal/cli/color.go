package cli

import (
	"io"
	"os"
)

// ANSI SGR sequences for the status marks.
const (
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
	ansiReset = "\x1b[0m"
)

// colorEnabled reports whether w is an interactive terminal that should receive
// ANSI color. It honors the NO_COLOR convention and TERM=dumb, and only colors
// when w is a real character device (so piped or file output stays plain, and
// tests writing to a buffer get no escape codes).
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// paint wraps s in the given ANSI color when on is true, otherwise returns s
// unchanged.
func paint(s, color string, on bool) string {
	if !on {
		return s
	}
	return color + s + ansiReset
}
