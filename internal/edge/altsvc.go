package edge

import (
	"bytes"
	"io"
	"net"
	"strings"
)

// altSvcConn is a tunnel stream whose first response head gets an Alt-Svc
// header, so a browser on the TCP ingress learns it can use HTTP/3. Only the
// first final response on a connection is touched: a browser remembers
// Alt-Svc for the origin, and later ones pass through untouched. Interim
// (1xx) responses before it pass unchanged. The head is left as it is when it
// is a protocol-switching (101) response, already carries Alt-Svc, uses bare
// LF line endings, or cannot be read as a response head within
// maxHeaderBytes; in each case the bytes go to the client unchanged.
type altSvcConn struct {
	net.Conn
	value   string
	pending []byte // bytes ready for the client (a head, possibly edited)
	rest    []byte // bytes read past the heads dealt with so far
	done    bool   // the first final head has been dealt with
	tmp     []byte // read buffer while collecting heads
}

func newAltSvcConn(c net.Conn, value string) *altSvcConn {
	return &altSvcConn{Conn: c, value: value}
}

func (a *altSvcConn) Read(b []byte) (int, error) {
	if len(a.pending) > 0 {
		n := copy(b, a.pending)
		a.pending = a.pending[n:]
		return n, nil
	}
	if a.done {
		return a.Conn.Read(b)
	}
	// Collect the next head before passing anything on. Interim (1xx)
	// responses go through as they are, and the head after them is the one
	// annotated.
	buf := a.rest
	a.rest = nil
	if a.tmp == nil {
		a.tmp = make([]byte, 4096)
	}
	for {
		if end, crlf := headEnd(buf); end >= 0 {
			next := end + 4 // past the blank line
			if !crlf {
				next = end + 2
			}
			switch {
			case !crlf || end > maxHeaderBytes:
				a.done = true // passed on as it is
				a.pending = buf
			case isInterim(buf[:end]):
				a.pending, a.rest = buf[:next], buf[next:] // and keep looking
			default:
				a.done = true
				a.pending = withAltSvc(buf, end, a.value)
			}
			if a.done {
				a.tmp = nil // not needed past the first head
			}
			return a.Read(b)
		}
		if len(buf) > maxHeaderBytes {
			a.done = true // no head in sight: hand over what arrived
			a.pending = buf
			return a.Read(b)
		}
		n, err := a.Conn.Read(a.tmp)
		buf = append(buf, a.tmp[:n]...)
		if err != nil && n == 0 {
			a.done = true
			a.pending = buf
			if len(buf) == 0 {
				return 0, err
			}
			return a.Read(b)
		}
	}
}

// isInterim reports a 1xx response head other than 101 (after which the
// connection carries another protocol).
func isInterim(head []byte) bool {
	code, ok := statusCode(head)
	return ok && code[0] == '1' && code != "101"
}

// statusCode returns the status code of a response head's status line.
func statusCode(head []byte) (string, bool) {
	line, _, _ := bytes.Cut(head, []byte("\n")) // only the status line is copied below
	f := strings.Fields(string(line))
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") || len(f[1]) != 3 {
		return "", false
	}
	return f[1], true
}

// headEnd finds the end of a response head in buf, as clients do: the first
// line break followed by an empty line, whatever mix of CRLF and bare LF the
// lines use. It returns the index of the line break ending the last header
// line and whether the whole head uses CRLF; only such a head is annotated,
// any other is passed on as it is.
func headEnd(buf []byte) (end int, crlf bool) {
	for i := bytes.IndexByte(buf, '\n'); i >= 0 && i+1 < len(buf); {
		next := buf[i+1:]
		if next[0] == '\n' || len(next) > 1 && next[0] == '\r' && next[1] == '\n' {
			end = i
			if i > 0 && buf[i-1] == '\r' {
				end = i - 1
			}
			crlf = end == i-1 && next[0] == '\r' && !hasBareLF(buf[:i+1])
			return end, crlf
		}
		j := bytes.IndexByte(next, '\n')
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return -1, false
}

// hasBareLF reports a line feed in b not preceded by a carriage return.
func hasBareLF(b []byte) bool {
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			return true
		}
	}
	return false
}

// withAltSvc returns buf (a response head ending at end, then any body
// bytes) with an Alt-Svc line added to the head when it is due one.
func withAltSvc(buf []byte, end int, value string) []byte {
	head := buf[:end]
	if code, ok := statusCode(head); !ok || code[0] == '1' {
		return buf // not a response line, or an interim / switching response
	}
	_, fields, _ := bytes.Cut(head, []byte("\r\n"))
	for len(fields) > 0 {
		var l []byte
		l, fields, _ = bytes.Cut(fields, []byte("\r\n"))
		if name, _, ok := bytes.Cut(l, []byte(":")); ok && bytes.EqualFold(bytes.TrimSpace(name), []byte("alt-svc")) {
			return buf // the service set its own
		}
	}
	out := make([]byte, 0, len(buf)+len(value)+11)
	out = append(out, head...)
	out = append(out, "\r\nAlt-Svc: "...)
	out = append(out, value...)
	return append(out, buf[end:]...)
}

var _ io.Reader = (*altSvcConn)(nil)
