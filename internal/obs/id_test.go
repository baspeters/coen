package obs

import (
	"errors"
	"testing"
)

func TestNewIDFallsBackWhenRandFails(t *testing.T) {
	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("csprng unavailable") }
	t.Cleanup(func() { randRead = old })

	id := NewID()
	if len(id) != 12 || id == "000000000000" {
		t.Fatalf("expected a non-zero fallback id, got %q", id)
	}
}
