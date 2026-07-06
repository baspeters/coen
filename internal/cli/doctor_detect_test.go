package cli

import (
	"strings"
	"testing"
)

func TestDoctorAutoDetectNoDaemon(t *testing.T) {
	old := enumerate
	t.Cleanup(func() { enumerate = old })
	enumerate = func() ([]daemon, error) { return nil, nil }

	out, err := runCLI(t, "doctor")
	if err == nil || !strings.Contains(err.Error()+out, "no running coen daemon") {
		t.Fatalf("want a no-daemon auto-detect error, got %v / %q", err, out)
	}
}
