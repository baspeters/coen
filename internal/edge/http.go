package edge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/baspeters/coen/internal/route"
	"github.com/baspeters/coen/internal/tunnel"
)

const maxHeaderBytes = 64 << 10

// errNoRequest reports a connection that closed (EOF), was reset, or hit the
// read-header deadline before any byte of a request was read. Health checks
// and preconnects end all three ways: a TLS 1.3 client that closes without
// reading the server's session ticket makes its kernel send an RST, and a
// browser may hold a preconnected socket idle past the deadline. The deadline
// still cuts such connections off (slow-loris protection); they are just not
// malformed requests. A TLS handshake failure with an alert stays a bad
// request. On the TLS ingress a close, reset, or timeout can also end a
// handshake the client abandoned after its ClientHello; handleIngress uses
// closedWithoutRequest to tell those apart.
var errNoRequest = errors.New("connection ended before a request was sent")

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
			// A TCP reset counts here too (unlike tunnel.IsTeardown, used for the
			// tunnel handshake): on the public ingress, health checks and TLS 1.3
			// preconnects commonly end with an RST. closedWithoutRequest still
			// counts a TLS handshake abandoned after its ClientHello.
			if len(buf) == 0 && (tunnel.IsTeardown(rerr) || errors.Is(rerr, syscall.ECONNRESET) || errors.Is(rerr, os.ErrDeadlineExceeded)) {
				// Wrap the cause so the caller can tell an idle timeout apart.
				return nil, "", fmt.Errorf("%w: %w", errNoRequest, rerr)
			}
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
