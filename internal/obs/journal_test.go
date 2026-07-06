package obs

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func newTestJournal(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	lv.Set(LevelTrace)
	return slog.New(newJournalHandler(&buf, lv)), &buf
}

func TestJournalRendersStyle2(t *testing.T) {
	log, buf := newTestJournal(t)
	log.Info("stream.closed", "conn_id", "abc", "host", "tweake.rs", "bytes_in", 355)
	got := buf.String()
	want := "<6>stream closed, conn_id=abc, host=tweake.rs, bytes_in=355\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestJournalNoAttrsHasNoTrailingComma(t *testing.T) {
	log, buf := newTestJournal(t)
	log.Info("tunnel.listen")
	if got := buf.String(); got != "<6>tunnel listen\n" {
		t.Fatalf("got %q", got)
	}
}

func TestJournalLevelPrefixes(t *testing.T) {
	cases := map[slog.Level]string{
		slog.LevelError: "<3>", slog.LevelWarn: "<4>",
		slog.LevelInfo: "<6>", slog.LevelDebug: "<7>", LevelTrace: "<7>",
	}
	for lvl, prefix := range cases {
		log, buf := newTestJournal(t)
		log.Log(context.Background(), lvl, "e.vent")
		if !strings.HasPrefix(buf.String(), prefix) {
			t.Fatalf("level %v: got %q want prefix %q", lvl, buf.String(), prefix)
		}
	}
}

func TestJournalQuotesWhenNeeded(t *testing.T) {
	log, buf := newTestJournal(t)
	log.Info("e.vent", "err", "dial failed, refused", "fp", "SHA256:aa=", "empty", "")
	got := buf.String()
	for _, sub := range []string{`err="dial failed, refused"`, `fp="SHA256:aa="`, `empty=""`} {
		if !strings.Contains(got, sub) {
			t.Fatalf("missing %q in %q", sub, got)
		}
	}
}

func TestJournalWithAttrsOrder(t *testing.T) {
	log, buf := newTestJournal(t)
	log.With("conn_id", "c1").With("host", "h1").Info("stream.accept", "n", 1)
	want := "<6>stream accept, conn_id=c1, host=h1, n=1\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestJournalConcurrentWritesAreWholeLines(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	log := slog.New(newJournalHandler(&buf, lv))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); log.Info("stream.closed", "k", "v") }()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("got %d lines, want 50", len(lines))
	}
	for _, ln := range lines {
		if ln != "<6>stream closed, k=v" {
			t.Fatalf("interleaved/garbled line: %q", ln)
		}
	}
}

func TestJournalInlinesEmptyKeyGroupAndSkipsEmptyGroup(t *testing.T) {
	log, buf := newTestJournal(t)
	// empty-key group inlines its attrs; empty group is dropped.
	log.Info("e.vent", slog.Group("", slog.String("a", "1")), slog.Group("g"))
	if got := buf.String(); got != "<6>e vent, a=1\n" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveFormatExplicitAndAutodetect(t *testing.T) {
	if got := resolveFormat("journal", io.Discard); got != "journal" {
		t.Fatalf("explicit journal: %q", got)
	}
	if got := resolveFormat("TEXT", io.Discard); got != "text" {
		t.Fatalf("case-insensitive text: %q", got)
	}
	t.Setenv("JOURNAL_STREAM", "")
	if got := resolveFormat("", io.Discard); got != "text" {
		t.Fatalf("unset with no JOURNAL_STREAM should be text: %q", got)
	}
	t.Setenv("JOURNAL_STREAM", "8:99")
	if got := resolveFormat("", io.Discard); got != "text" {
		t.Fatalf("non-*os.File writer should be text: %q", got)
	}
}

func TestNewLoggerJournalFormat(t *testing.T) {
	var buf bytes.Buffer
	log, _, err := NewLogger("info", "journal", &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("tunnel.established", "tls", "1.3")
	if got := buf.String(); got != "<6>tunnel established, tls=1.3\n" {
		t.Fatalf("got %q", got)
	}
}

func TestJournalWithGroup(t *testing.T) {
	log, buf := newTestJournal(t)
	log.WithGroup("outer").Info("e.vent",
		"k", "v",
		slog.Group("g", slog.Int("n", 1)),
	)
	want := "<6>e vent, outer.k=v, outer.g.n=1\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestJournalNestedGroups(t *testing.T) {
	log, buf := newTestJournal(t)
	log.WithGroup("a").WithGroup("b").Info("m", "k", 1)
	if got := buf.String(); got != "<6>m, a.b.k=1\n" {
		t.Fatalf("got %q", got)
	}
}

func TestJournalWithEmptyAttrsAndGroupReturnSameHandler(t *testing.T) {
	var buf bytes.Buffer
	h := newJournalHandler(&buf, new(slog.LevelVar))
	if h.WithAttrs(nil) != h {
		t.Fatal("WithAttrs(nil) should return the same handler")
	}
	if h.WithGroup("") != h {
		t.Fatal(`WithGroup("") should return the same handler`)
	}
}

func TestJournalAppendAttrSkipsZeroAttr(t *testing.T) {
	var b strings.Builder
	appendAttr(&b, "", slog.Attr{})
	if b.String() != "" {
		t.Fatalf("zero attr should produce nothing, got %q", b.String())
	}
}

func TestParseJournalStream(t *testing.T) {
	if d, i, ok := parseJournalStream("12:34"); !ok || d != 12 || i != 34 {
		t.Fatalf("parse 12:34 = %d,%d,%v", d, i, ok)
	}
	for _, bad := range []string{"", "nope", "12", "12:", ":34", "a:b"} {
		if _, _, ok := parseJournalStream(bad); ok {
			t.Fatalf("parseJournalStream(%q) should fail", bad)
		}
	}
}
