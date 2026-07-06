package obs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

var randRead = rand.Read

// NewID returns a short random hex correlation id.
func NewID() string {
	var b [6]byte
	if _, err := randRead(b[:]); err != nil {
		// A CSPRNG read essentially never fails; if it does, fall back to a
		// time-based value so ids stay non-zero and distinct rather than a
		// constant "000000000000" that would collide across requests.
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], uint64(time.Now().UnixNano()))
		copy(b[:], t[2:]) // low 48 bits
	}
	return hex.EncodeToString(b[:])
}
