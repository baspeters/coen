package edge

import (
	"testing"
	"time"
)

// The public ingress read/handshake deadline must always be positive so it
// cannot be disabled (slow-loris protection), even if the config yields 0.
func TestReadHeaderDeadlineAlwaysPositive(t *testing.T) {
	if got := readHeaderDeadline(0); got != defaultReadHeaderTimeout {
		t.Fatalf("0 -> %v, want default %v", got, defaultReadHeaderTimeout)
	}
	if got := readHeaderDeadline(-5 * time.Second); got != defaultReadHeaderTimeout {
		t.Fatalf("negative -> %v, want default %v", got, defaultReadHeaderTimeout)
	}
	if got := readHeaderDeadline(50 * time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("positive -> %v, want it unchanged", got)
	}
}
