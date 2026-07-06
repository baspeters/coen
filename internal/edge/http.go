package edge

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/baspeters/coen/internal/route"
)

const maxHeaderBytes = 64 << 10

// readRequestHead reads an HTTP/1.x request head (up to and including the blank
// line) without reserializing it, returning the raw bytes and the normalized
// Host. It stops at maxBytes.
func readRequestHead(r io.Reader, maxBytes int) (head []byte, host string, err error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxBytes {
				return nil, "", fmt.Errorf("request head exceeds %d bytes", maxBytes)
			}
			if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
				h, herr := parseHost(buf[:idx])
				if herr != nil {
					return nil, "", herr
				}
				return buf, h, nil
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil, "", fmt.Errorf("incomplete request head")
			}
			return nil, "", rerr
		}
	}
}

func parseHost(head []byte) (string, error) {
	lines := bytes.Split(head, []byte("\r\n"))
	host := ""
	found := false
	for _, ln := range lines[1:] { // skip the request line
		if len(ln) >= 5 && strings.EqualFold(string(ln[:5]), "host:") {
			if found {
				// RFC 7230: reject a request carrying more than one Host header,
				// to avoid host-routing ambiguity between the edge and a backend.
				return "", fmt.Errorf("multiple Host headers")
			}
			host = route.Normalize(strings.TrimSpace(string(ln[5:])))
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("no Host header")
	}
	return host, nil
}
