package agent

import (
	"io"

	"github.com/baspeters/coen/internal/tunnel"
)

// writePreamble encodes p and writes it to w, as the edge does.
func writePreamble(w io.Writer, p tunnel.Preamble) error {
	b, err := tunnel.EncodePreamble(p)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
