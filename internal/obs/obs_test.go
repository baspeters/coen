package obs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
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

func TestSnapshotConnectedSinceOmitZero(t *testing.T) {
	// Test disconnected snapshot: connected_since should be absent
	var s State
	s.SetDisconnected()
	snap := s.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal disconnected snapshot: %v", err)
	}
	jsonStr := string(data)
	if strings.Contains(jsonStr, "connected_since") {
		t.Fatalf("disconnected snapshot should not contain connected_since, got: %s", jsonStr)
	}

	// Test connected snapshot: connected_since should be present
	var s2 State
	s2.SetConnected("SHA256:test")
	snap2 := s2.Snapshot()
	data2, err := json.Marshal(snap2)
	if err != nil {
		t.Fatalf("marshal connected snapshot: %v", err)
	}
	jsonStr2 := string(data2)
	if !strings.Contains(jsonStr2, "connected_since") {
		t.Fatalf("connected snapshot should contain connected_since, got: %s", jsonStr2)
	}

	// Verify the zero time is handled correctly
	var snap3 Snapshot
	snap3.TunnelConnected = false
	snap3.ConnectedSince = time.Time{}
	data3, err := json.Marshal(snap3)
	if err != nil {
		t.Fatalf("marshal zero time snapshot: %v", err)
	}
	if strings.Contains(string(data3), "connected_since") {
		t.Fatalf("zero time should be omitted, got: %s", string(data3))
	}
}
