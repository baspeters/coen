package obs

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a short random hex correlation id.
func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
