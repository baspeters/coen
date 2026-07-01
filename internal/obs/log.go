package obs

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// LevelTrace is a custom level below Debug for very verbose tracing.
const LevelTrace = slog.Level(-8)

func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

// NewLogger builds a slog.Logger and returns a LevelVar for runtime level changes.
func NewLogger(level, format string, w io.Writer) (*slog.Logger, *slog.LevelVar, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, nil, err
	}
	lv := new(slog.LevelVar)
	lv.Set(lvl)
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	case "text", "":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("unknown log format %q", format)
	}
	return slog.New(h), lv, nil
}
