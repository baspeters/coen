package edge

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/baspeters/coen/internal/pki"
)

// http1Head is the head serveHTTP3 sends for r.
func http1Head(r *http.Request) ([]byte, error) {
	lines, err := http1Lines(r)
	if err != nil {
		return nil, err
	}
	return framed(lines, r, trailerNames(r.Trailer)), nil
}

func TestHTTP1HeadFraming(t *testing.T) {
	mk := func(method string, length int64, hdr http.Header) *http.Request {
		if hdr == nil {
			hdr = http.Header{}
		}
		return &http.Request{Method: method, Host: "app.example.com", RequestURI: "/p?q=1", Header: hdr, ContentLength: length}
	}
	cases := []struct {
		r    *http.Request
		want []string
		not  []string
	}{
		{mk("GET", 0, nil), []string{"GET /p?q=1 HTTP/1.1\r\nHost: app.example.com\r\n"}, []string{"Content-Length", "Transfer-Encoding", "Connection"}},
		{mk("POST", 0, nil), []string{"Content-Length: 0\r\n"}, []string{"Transfer-Encoding"}},
		{mk("PUT", 12, nil), []string{"Content-Length: 12\r\n"}, nil},
		{mk("PATCH", -1, nil), []string{"Transfer-Encoding: chunked\r\n"}, []string{"Content-Length"}},
		{mk("GET", 0, http.Header{"Connection": {"keep-alive"}, "Upgrade": {"x"}, "Te": {"trailers"}, "Content-Length": {"9"}, "X-A": {"1", "2"}}),
			[]string{"X-A: 1\r\nX-A: 2\r\n"}, []string{"keep-alive", "Upgrade", "Te:", "Content-Length"}},
		{mk("GET", 0, http.Header{"Cookie": {"a=1", "b=2"}}), []string{"Cookie: a=1; b=2\r\n"}, nil},
		{&http.Request{Method: "POST", Host: "h", RequestURI: "/", Header: http.Header{}, ContentLength: 5, Trailer: http.Header{"Grpc-Status": nil, "Checksum": nil}},
			[]string{"Trailer: Checksum, Grpc-Status\r\nTransfer-Encoding: chunked\r\n"}, []string{"Content-Length"}},
	}
	for i, c := range cases {
		b, err := http1Head(c.r)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		for _, w := range c.want {
			if !strings.Contains(string(b), w) {
				t.Errorf("case %d: %q lacks %q", i, b, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(string(b), n) {
				t.Errorf("case %d: %q has %q", i, b, n)
			}
		}
	}
	bad := []*http.Request{
		{Method: "GET", Host: "", RequestURI: "/", Header: http.Header{}},
		{Method: "GET", Host: "a\r\nb", RequestURI: "/", Header: http.Header{}},
		{Method: "G T", Host: "a", RequestURI: "/", Header: http.Header{}},
		{Method: "GET", Host: "a", RequestURI: "/a b", Header: http.Header{}},
		mk("GET", 0, http.Header{"X-Bad": {"a\r\nInjected: 1"}}),
		mk("GET", 0, http.Header{"Bad Name": {"v"}}),
	}
	for i, r := range bad {
		if _, err := http1Head(r); err == nil {
			t.Errorf("bad case %d accepted", i)
		}
	}
}

func TestCopyResponseHeaderDropsConnectionLevel(t *testing.T) {
	src := http.Header{"Connection": {"X-Hop, close"}, "X-Hop": {"1"}, "Keep-Alive": {"timeout=5"}, "Transfer-Encoding": {"chunked"}, "X-End": {"2"}}
	dst := http.Header{}
	copyResponseHeader(dst, src)
	if len(dst) != 1 || dst.Get("X-End") != "2" {
		t.Fatalf("copied %v", dst)
	}
}

func TestReadFinalResponseSkipsInterim(t *testing.T) {
	in := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	var seen []int
	var link string
	resp, err := readFinalResponse(bufio.NewReader(strings.NewReader(in)), "GET", func(c int, h http.Header) {
		seen = append(seen, c)
		if c == 103 {
			link = h.Get("Link")
		}
	})
	if err != nil || resp.StatusCode != 200 || len(seen) != 2 || seen[0] != 100 || seen[1] != 103 || link != "</a>" {
		t.Fatalf("resp %v err %v interim %v link %q", resp, err, seen, link)
	}
	none := func(int, http.Header) {}
	if _, err := readFinalResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 101 Switching Protocols\r\n\r\n")), "GET", none); err == nil {
		t.Fatal("a 101 must be refused")
	}
	if _, err := readFinalResponse(bufio.NewReader(strings.NewReader("garbage")), "GET", none); err == nil {
		t.Fatal("a malformed response must be an error")
	}
}

func TestPeekBody(t *testing.T) {
	read := func(body io.Reader) string {
		b, err := io.ReadAll(body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// Empty: length 0.
	pb := peekBody(io.NopCloser(strings.NewReader("")), time.Second)
	if pb.length() != 0 || read(pb) != "" {
		t.Fatalf("empty body: %d", pb.length())
	}
	// All of it with EOF in the first read: its exact length.
	pb = peekBody(io.NopCloser(iotest.DataErrReader(strings.NewReader("hello"))), time.Second)
	if pb.length() != 5 || read(pb) != "hello" {
		t.Fatalf("whole body: %d", pb.length())
	}
	// More to come: chunked, nothing lost.
	pb = peekBody(io.NopCloser(io.MultiReader(strings.NewReader("part1-"), strings.NewReader("part2"))), time.Second)
	if pb.length() != -1 || read(pb) != "part1-part2" {
		t.Fatalf("a body in parts: %d", pb.length())
	}
	// Not started within the wait: chunked, and the body still arrives.
	pb = peekBody(&slowBody{r: strings.NewReader("late"), delay: 100 * time.Millisecond}, 10*time.Millisecond)
	if pb.done() || pb.length() != -1 {
		t.Fatal("a late body must go chunked")
	}
	if got := read(pb); got != "late" {
		t.Fatalf("late body read %q", got)
	}
	// A failed first read is kept for the caller.
	pb = peekBody(errBody{}, time.Second)
	if !pb.done() || pb.err == nil {
		t.Fatal("a failed read must be reported")
	}
}

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("stream reset") }
func (errBody) Close() error             { return nil }

// slowBody delivers its content only after a delay.
type slowBody struct {
	r     io.Reader
	delay time.Duration
}

func (s *slowBody) Read(b []byte) (int, error) { time.Sleep(s.delay); s.delay = 0; return s.r.Read(b) }
func (s *slowBody) Close() error               { return nil }

func TestResetKeyIsStable(t *testing.T) {
	ca, err := pki.CreateCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := ca.IssueServer("127.0.0.1")
	c1, _ := tls.X509KeyPair(certPEM, keyPEM)
	c2, _ := tls.X509KeyPair(certPEM, keyPEM) // the same files, loaded again (a restart)
	k1, k2 := resetKey(c1), resetKey(c2)
	if k1 == nil || *k1 != *k2 {
		t.Fatal("the reset key must be the same across restarts")
	}
	otherPEM, otherKey, _ := ca.IssueServer("127.0.0.1")
	c3, _ := tls.X509KeyPair(otherPEM, otherKey)
	if *resetKey(c3) == *k1 {
		t.Fatal("another key must give another reset key")
	}
	if resetKey(tls.Certificate{}) != nil {
		t.Fatal("without a usable private key, resets stay off")
	}
}

// Trailers the client sends without announcing them still cross when the
// body goes chunked: they are known once the body has ended.
func TestSendBodyUnannouncedTrailers(t *testing.T) {
	r := &http.Request{Method: "POST", ContentLength: -1}
	body := &trailerSetter{r: strings.NewReader("data"), req: r}
	var out strings.Builder
	if err := sendBody(&out, body, r, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "0\r\nX-Sum: 42\r\n\r\n") {
		t.Fatalf("chunked body %q lacks the trailer", out.String())
	}
}

// trailerSetter sets the request's trailers when its body ends, as the
// HTTP/3 server does.
type trailerSetter struct {
	r   io.Reader
	req *http.Request
}

func (s *trailerSetter) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if err == io.EOF {
		s.req.Trailer = http.Header{"X-Sum": {"42"}}
	}
	return n, err
}
