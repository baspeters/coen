package tunnel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Preamble is the small header the edge writes at the start of each stream
// so the agent can log the same conn_id and know the original client address.
type Preamble struct {
	ConnID     string `json:"conn_id"`
	ClientAddr string `json:"client_addr"`
	Host       string `json:"host"`
	// EdgeVersion is the edge's build version, so the agent can warn on a
	// version skew. Omitted (and thus empty on an older edge) for compatibility.
	EdgeVersion string `json:"edge_version,omitempty"`
}

const maxPreamble = 4096

// EncodePreamble returns p framed for the wire (a 2-byte length, then JSON),
// or an error before anything is sent if it is too large. Callers send the
// frame in one write, so a stream cut mid-way never leaves a lone length
// prefix that the reader would take for a truncated header.
func EncodePreamble(p Preamble) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > maxPreamble {
		return nil, fmt.Errorf("preamble too large: %d bytes", len(b))
	}
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(b)))
	copy(frame[2:], b)
	return frame, nil
}

func ReadPreamble(r io.Reader) (Preamble, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Preamble{}, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxPreamble {
		return Preamble{}, fmt.Errorf("preamble too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF {
			// The length prefix arrived but no body byte did (ReadFull into a
			// non-empty buffer): the header is truncated, not a stream that
			// closed before sending anything.
			err = io.ErrUnexpectedEOF
		}
		return Preamble{}, err
	}
	var p Preamble
	if err := json.Unmarshal(buf, &p); err != nil {
		return Preamble{}, err
	}
	return p, nil
}
