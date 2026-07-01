package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{"trace": LevelTrace, "debug": slog.LevelDebug, "info": slog.LevelInfo, "": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLevel("nope"); err == nil {
		t.Fatal("expected error for bad level")
	}
}

func TestNewLoggerEmitsAndLevelVarControls(t *testing.T) {
	var buf bytes.Buffer
	log, lv, err := NewLogger("info", "text", &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hidden")
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug should be suppressed at info level")
	}
	lv.Set(slog.LevelDebug)
	log.Debug("nowvisible")
	if !strings.Contains(buf.String(), "nowvisible") {
		t.Fatal("debug should appear after LevelVar change")
	}
}

func TestNewIDUnique(t *testing.T) {
	if NewID() == NewID() {
		t.Fatal("IDs should be unique")
	}
}

func TestStateSnapshot(t *testing.T) {
	var s State
	s.SetConnected("SHA256:abc")
	s.StreamOpened()
	s.StreamClosed(10, 20)
	s.Reconnect()
	snap := s.Snapshot()
	if !snap.TunnelConnected || snap.TotalStreams != 1 || snap.ActiveStreams != 0 {
		t.Fatalf("bad snapshot: %+v", snap)
	}
	if snap.BytesIn != 10 || snap.BytesOut != 20 || snap.Reconnects != 1 {
		t.Fatalf("bad counters: %+v", snap)
	}
	if snap.PeerFingerprint != "SHA256:abc" {
		t.Fatalf("bad fp: %+v", snap)
	}
}
