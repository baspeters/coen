package obs

import (
	"sync"
	"testing"
)

func TestRouteStatsNilSafe(t *testing.T) {
	var r *RouteStats
	r.opened()
	r.closed()
	r.Bytes().AddIn(1)
	r.Bytes().AddOut(2)
	r.Failure(ReasonDialError) // must not panic
	s := NewState("agent")
	s.StreamOpened(nil)
	s.Route("t").Bytes().AddIn(3)
	s.Route("t").Bytes().AddOut(4)
	s.StreamClosed(nil)
	if snap := s.Snapshot(); snap.TotalStreams != 1 || snap.BytesIn != 3 || snap.ActiveStreams != 0 {
		t.Fatalf("a nil route must still update the global counters: %+v", snap)
	}
}

func TestRouteIsIdempotentAndDetailSorted(t *testing.T) {
	s := NewState("edge")
	b := s.Route("b.example.com")
	if s.Route("b.example.com") != b {
		t.Fatal("Route must return the same stats for the same pattern")
	}
	a := s.Route("a.example.com")
	s.StreamOpened(a)
	s.StreamOpened(a)
	a.Bytes().AddIn(5)
	a.Bytes().AddOut(7)
	s.StreamClosed(a)
	a.Failure(ReasonNoAgent)
	a.Failure(ReasonNoAgent)
	s.Failure(ReasonBadRequest)
	s.ExpectAgents(map[string]bool{"SHA256:z": true, "SHA256:y": true, "SHA256:off": false})
	s.ExpectAgents(map[string]bool{"SHA256:y": true})

	d := s.Detail()
	if len(d.Routes) != 2 || d.Routes[0].Pattern != "a.example.com" || d.Routes[1].Pattern != "b.example.com" {
		t.Fatalf("routes not sorted by pattern: %+v", d.Routes)
	}
	got := d.Routes[0]
	if got.Active != 1 || got.Total != 2 || got.BytesIn != 5 || got.BytesOut != 7 || got.Failures.Get(ReasonNoAgent) != 2 {
		t.Fatalf("unexpected route snapshot: %+v", got)
	}
	if d.UnroutedFailures.Get(ReasonBadRequest) != 1 {
		t.Fatalf("unrouted failures = %v", d.UnroutedFailures)
	}
	if len(d.ExpectedAgents) != 2 || d.ExpectedAgents[0] != "SHA256:y" {
		t.Fatalf("expected agents = %v", d.ExpectedAgents)
	}
	if d.TotalStreams != 2 || d.ActiveStreams != 1 || d.BytesOut != 7 {
		t.Fatalf("global counters must move with the route counters: %+v", d.Snapshot)
	}
	if d.StartTime.IsZero() || d.Role != "edge" {
		t.Fatalf("Detail should carry the start time and role: %+v", d)
	}
}

// Counters are updated from many goroutines at once; run under -race.
func TestRouteStatsConcurrent(t *testing.T) {
	s := NewState("agent")
	r := s.Route("*")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.StreamOpened(r)
			r.Failure(ReasonDialError)
			s.Failure(ReasonNoRoute)
			_ = s.Detail()
			r.Bytes().AddIn(1)
			r.Bytes().AddOut(1)
			s.StreamClosed(r)
		}()
	}
	wg.Wait()
	d := s.Detail().Routes[0]
	if d.Active != 0 || d.Total != 50 || d.BytesIn != 50 || d.Failures.Get(ReasonDialError) != 50 {
		t.Fatalf("lost updates: %+v", d)
	}
}

func TestReasonNamesAndTables(t *testing.T) {
	seen := map[string]bool{}
	for r := Reason(0); r < numReasons; r++ {
		name := r.String()
		if name == "" || seen[name] {
			t.Fatalf("reason %d has an empty or duplicate name %q", r, name)
		}
		seen[name] = true
	}
	if Reason(200).String() != "unknown" {
		t.Fatal("out-of-range reason must render as unknown")
	}
	var c reasonCounts
	c.inc(Reason(200)) // out of range: ignored, must not panic
	if c.snapshot() != (ReasonCounts{}) {
		t.Fatal("an out-of-range reason must not be counted")
	}
	if (ReasonCounts{}).Get(Reason(200)) != 0 {
		t.Fatal("Get of an out-of-range reason must be 0")
	}
	// Every reason belongs to at least one role table, so none is reported
	// only after its first occurrence.
	listed := map[Reason]bool{}
	for _, tbl := range [][]Reason{EdgeUnroutedReasons, EdgeRouteReasons, AgentUnroutedReasons, AgentRouteReasons} {
		for _, r := range tbl {
			listed[r] = true
		}
	}
	for r := Reason(0); r < numReasons; r++ {
		if !listed[r] {
			t.Errorf("reason %s is in no role table", r)
		}
	}
}

// Bytes spread over shards still add up, and a nil route counts nothing.
func TestStreamBytesShardsSum(t *testing.T) {
	s := NewState("edge")
	r := s.Route("*")
	for i := 0; i < 3*byteShards; i++ {
		b := r.Bytes()
		b.AddIn(10)
		b.AddOut(1)
	}
	in, out := r.byteTotals()
	if in != 30*byteShards || out != 3*byteShards {
		t.Fatalf("totals = %d/%d", in, out)
	}
	if snap := s.Snapshot(); snap.BytesIn != in || snap.BytesOut != out {
		t.Fatalf("snapshot = %d/%d, want %d/%d", snap.BytesIn, snap.BytesOut, in, out)
	}
	var nilRoute *RouteStats
	nb := nilRoute.Bytes()
	nb.AddIn(5) // must not panic
	nb.AddOut(5)
}
