package edge

import (
	"io"
	"net"
	"strings"
	"testing"
)

// pipeConn serves canned bytes as a net.Conn read side.
type pipeConn struct {
	net.Conn
	r io.Reader
}

func (p *pipeConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// oneByte reads one byte at a time, to split the head across reads.
type oneByte struct{ r io.Reader }

func (o oneByte) Read(b []byte) (int, error) { return o.r.Read(b[:1]) }

func TestAltSvcInjection(t *testing.T) {
	const v = `h3=":443"; ma=86400`
	cases := []struct{ in, want string }{
		{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAlt-Svc: " + v + "\r\n\r\nok"},
		{"HTTP/1.1 200 OK\r\nalt-svc: clear\r\n\r\n", "HTTP/1.1 200 OK\r\nalt-svc: clear\r\n\r\n"},
		{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nframes", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nframes"},
		{"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nAlt-Svc: " + v + "\r\n\r\n"},
		{"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
			"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 204 No Content\r\nAlt-Svc: " + v + "\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"}, // only the first final head
		{"not http at all\r\n\r\n", "not http at all\r\n\r\n"},
		{"HTTP/1.1 200 OK\r\nX: truncated", "HTTP/1.1 200 OK\r\nX: truncated"},
		{"", ""},
		{"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi", "HTTP/1.1 200 OK\nContent-Length: 2\n\nhi"},                                                                 // bare LF: untouched
		{"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\n\r\ndata", "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\n\r\ndata"},                         // mixed endings: found, untouched
		{"HTTP/1.1 103\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 103\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nAlt-Svc: " + v + "\r\n\r\n"}, // no reason phrase
	}
	for i, c := range cases {
		for _, split := range []bool{false, true} {
			var r io.Reader = strings.NewReader(c.in)
			if split {
				r = oneByte{r}
			}
			got, err := io.ReadAll(newAltSvcConn(&pipeConn{r: r}, v))
			if err != nil || string(got) != c.want {
				t.Errorf("case %d split=%v: %q (%v), want %q", i, split, got, err, c.want)
			}
		}
	}
	// A bare-LF head is passed on as soon as it is complete, not held until
	// the connection closes.
	pr, pw := net.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("HTTP/1.1 200 OK\nContent-Length: 2\n\nhi")) }()
	buf := make([]byte, 64)
	n, err := newAltSvcConn(pr, v).Read(buf)
	if err != nil || !strings.HasPrefix("HTTP/1.1 200 OK\nContent-Length: 2\n\nhi", string(buf[:n])) || n == 0 {
		t.Fatalf("bare-LF head read = %q, %v", buf[:n], err)
	}
	// A head larger than maxHeaderBytes passes through unchanged.
	big := "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", maxHeaderBytes) + "\r\n\r\n"
	if got, _ := io.ReadAll(newAltSvcConn(&pipeConn{r: strings.NewReader(big)}, v)); string(got) != big {
		t.Fatal("an oversized head was changed")
	}
}
