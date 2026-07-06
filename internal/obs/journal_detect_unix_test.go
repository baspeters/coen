//go:build unix

package obs

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAutodetectMatchesJournalStream(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	t.Setenv("JOURNAL_STREAM", fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)))

	if !writerIsJournalStream(f) {
		t.Fatal("expected writerIsJournalStream to match the temp file")
	}
	if got := resolveFormat("", f); got != "journal" {
		t.Fatalf("unset format with matching JOURNAL_STREAM should be journal, got %q", got)
	}

	// A mismatched inode must not match.
	t.Setenv("JOURNAL_STREAM", fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)+1))
	if writerIsJournalStream(f) {
		t.Fatal("mismatched inode should not match")
	}
}
