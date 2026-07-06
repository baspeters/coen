package obs

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
)

// journalHandler renders slog records for systemd's journald: a syslog priority
// prefix (which journald parses into a real priority and strips), the event id
// with dots turned into spaces, then attributes as key=value joined by ", ".
// It emits no timestamp (journald supplies one) and no level= text.
type journalHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	lv    *slog.LevelVar
	attrs []slog.Attr
	group string
}

func newJournalHandler(w io.Writer, lv *slog.LevelVar) *journalHandler {
	return &journalHandler{mu: &sync.Mutex{}, w: w, lv: lv}
}

func (h *journalHandler) Enabled(_ context.Context, l slog.Level) bool {
	min := slog.LevelInfo
	if h.lv != nil {
		min = h.lv.Level()
	}
	return l >= min
}

func (h *journalHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(journalPrefix(r.Level))
	b.WriteString(strings.ReplaceAll(r.Message, ".", " "))
	for _, a := range h.attrs {
		appendAttr(&b, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, h.group, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *journalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := *h
	nh.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	nh.attrs = append(nh.attrs, h.attrs...)
	nh.attrs = append(nh.attrs, attrs...)
	return &nh
}

func (h *journalHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	if h.group == "" {
		nh.group = name
	} else {
		nh.group = h.group + "." + name
	}
	return &nh
}

func journalPrefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "<3>"
	case l >= slog.LevelWarn:
		return "<4>"
	case l >= slog.LevelInfo:
		return "<6>"
	default:
		return "<7>"
	}
}

// appendAttr writes ", key=value" for a resolved attribute, following slog's
// grouping rules: an empty group is dropped, an empty-key group is inlined, and
// a zero attr is skipped.
func appendAttr(b *strings.Builder, group string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		gattrs := a.Value.Group()
		if len(gattrs) == 0 {
			return
		}
		sub := group
		if a.Key != "" {
			if sub == "" {
				sub = a.Key
			} else {
				sub = sub + "." + a.Key
			}
		}
		for _, ga := range gattrs {
			appendAttr(b, sub, ga)
		}
		return
	}
	if a.Equal(slog.Attr{}) {
		return
	}
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	b.WriteString(", ")
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(journalQuote(a.Value.String()))
}

// journalQuote quotes a value when it is empty or contains a byte that would
// make the "key=value, " layout ambiguous or hard to read.
func journalQuote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return r <= ' ' || r == '"' || r == '=' || r == ','
	}) >= 0 {
		return strconv.Quote(s)
	}
	return s
}

// writerIsJournalStream reports whether w is the stream systemd connected to the
// journal, by matching the writer's device:inode against $JOURNAL_STREAM.
func writerIsJournalStream(w io.Writer) bool {
	js := os.Getenv("JOURNAL_STREAM")
	if js == "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	dev, ino, ok := parseJournalStream(js)
	if !ok {
		return false
	}
	return fileMatchesDevIno(f, dev, ino)
}

func parseJournalStream(s string) (dev, ino uint64, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return 0, 0, false
	}
	d, err1 := strconv.ParseUint(s[:i], 10, 64)
	n, err2 := strconv.ParseUint(s[i+1:], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return d, n, true
}
