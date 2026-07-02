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
}

const maxPreamble = 4096

func WritePreamble(w io.Writer, p Preamble) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(b) > maxPreamble {
		return fmt.Errorf("preamble too large: %d bytes", len(b))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
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
		return Preamble{}, err
	}
	var p Preamble
	if err := json.Unmarshal(buf, &p); err != nil {
		return Preamble{}, err
	}
	return p, nil
}
