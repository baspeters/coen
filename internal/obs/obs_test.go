package obs

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestNewLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	log, _, err := NewLogger("info", "json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "key", "value")

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json format did not emit valid JSON: %v (line=%q)", err, buf.String())
	}
	if decoded["msg"] != "hello" {
		t.Fatalf("bad msg field: %+v", decoded)
	}
	if decoded["key"] != "value" {
		t.Fatalf("bad key field: %+v", decoded)
	}
}

func TestNewLoggerUnknownFormat(t *testing.T) {
	if _, _, err := NewLogger("info", "xml", io.Discard); err == nil {
		t.Fatal("expected error for unknown log format")
	}
}

func TestNewLoggerInvalidLevel(t *testing.T) {
	if _, _, err := NewLogger("bogus", "text", io.Discard); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestNewIDUnique(t *testing.T) {
	a, b := NewID(), NewID()
	if a == b {
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

func TestStateHandshakeErrorAndDisconnect(t *testing.T) {
	var s State
	s.HandshakeFail()
	s.HandshakeFail()
	s.HandshakeOK()
	s.SetError("boom")
	s.Reconnect()
	s.Reconnect()

	s.SetConnected("SHA256:xyz")
	s.StreamOpened()
	s.StreamOpened()
	s.StreamClosed(3, 4) // one of two streams closes; active count should decrement, not zero

	snap := s.Snapshot()
	if snap.HandshakeFail != 2 {
		t.Fatalf("HandshakeFail = %d, want 2", snap.HandshakeFail)
	}
	if snap.HandshakeOK != 1 {
		t.Fatalf("HandshakeOK = %d, want 1", snap.HandshakeOK)
	}
	if snap.LastError != "boom" {
		t.Fatalf("LastError = %q, want %q", snap.LastError, "boom")
	}
	if snap.Reconnects != 2 {
		t.Fatalf("Reconnects = %d, want 2", snap.Reconnects)
	}
	if snap.TotalStreams != 2 {
		t.Fatalf("TotalStreams = %d, want 2", snap.TotalStreams)
	}
	if snap.ActiveStreams != 1 {
		t.Fatalf("ActiveStreams = %d, want 1 (one of two streams closed)", snap.ActiveStreams)
	}
	if snap.BytesIn != 3 || snap.BytesOut != 4 {
		t.Fatalf("bytes = in:%d out:%d, want in:3 out:4", snap.BytesIn, snap.BytesOut)
	}

	s.SetDisconnected()
	snap2 := s.Snapshot()
	if snap2.TunnelConnected {
		t.Fatal("expected TunnelConnected=false after SetDisconnected")
	}
	if !snap2.ConnectedSince.IsZero() {
		t.Fatalf("expected zero ConnectedSince once disconnected, got %v", snap2.ConnectedSince)
	}
	if snap2.PeerFingerprint != "" {
		t.Fatalf("peer fingerprint should be cleared after disconnect, got %q", snap2.PeerFingerprint)
	}
	// Disconnecting must not clobber counters accumulated before it.
	if snap2.HandshakeFail != 2 || snap2.HandshakeOK != 1 || snap2.LastError != "boom" {
		t.Fatalf("SetDisconnected should not reset other counters: %+v", snap2)
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

func TestAgentSet(t *testing.T) {
	var s State
	s.AgentConnected("AA", "10.0.0.1:1000")
	s.AgentConnected("BB", "10.0.0.2:2000")
	snap := s.Snapshot()
	if len(snap.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(snap.Agents))
	}
	byFP := map[string]string{}
	for _, a := range snap.Agents {
		byFP[a.Fingerprint] = a.RemoteAddr
	}
	if byFP["AA"] != "10.0.0.1:1000" {
		t.Fatalf("agent AA remote_addr = %q, want 10.0.0.1:1000", byFP["AA"])
	}
	s.AgentDisconnected("AA")
	if got := len(s.Snapshot().Agents); got != 1 {
		t.Fatalf("agents after disconnect = %d, want 1", got)
	}
}

func TestNewStateTagsSnapshotRole(t *testing.T) {
	if r := NewState("edge").Snapshot().Role; r != "edge" {
		t.Fatalf("edge snapshot role = %q, want edge", r)
	}
	if r := NewState("agent").Snapshot().Role; r != "agent" {
		t.Fatalf("agent snapshot role = %q, want agent", r)
	}
	if r := (&State{}).Snapshot().Role; r != "" {
		t.Fatalf("untagged snapshot role = %q, want empty", r)
	}
}
