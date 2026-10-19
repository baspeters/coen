package netx_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/netx"
	"github.com/baspeters/coen/internal/netx/proxytest"
	"github.com/baspeters/coen/internal/pki"
)

// echoServer answers each connection by echoing what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// roundTrip writes msg on c and reads it back.
func roundTrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func TestDialDirect(t *testing.T) {
	addr := echoServer(t)
	c, err := netx.Dial(context.Background(), addr, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c, "hello"); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestDialThroughProxy(t *testing.T) {
	addr := echoServer(t)
	p := proxytest.Start(t, proxytest.Options{User: "agent", Password: "s3cr:t"})
	c, err := netx.Dial(context.Background(), addr, p.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c, "through the proxy"); got != "through the proxy" {
		t.Fatalf("got %q", got)
	}
	if tg := p.Targets(); len(tg) != 1 || tg[0] != addr {
		t.Fatalf("the proxy saw CONNECT to %v, want %s", tg, addr)
	}
}

// Bytes the proxy sends right after its 200 belong to the tunnel.
func TestDialKeepsBytesAfterTheAnswer(t *testing.T) {
	addr := echoServer(t)
	p := proxytest.Start(t, proxytest.Options{EarlyBytes: "early:"})
	c, err := netx.Dial(context.Background(), addr, p.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c, "x"); got != "e" {
		t.Fatalf("the first tunnel byte was %q, want the proxy's early byte", got)
	}
	rest := make([]byte, len("arly:x"))
	if _, err := io.ReadFull(c, rest); err != nil || string(rest) != "arly:x" {
		t.Fatalf("got %q, %v", rest, err)
	}
}

func TestDialThroughHTTPSProxy(t *testing.T) {
	addr := echoServer(t)
	ca, _ := pki.CreateCA()
	certPEM, keyPEM, _ := ca.IssueServer("127.0.0.1")
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	p := proxytest.Start(t, proxytest.Options{TLS: &cert})
	if _, err := netx.Dial(context.Background(), addr, p.URL, time.Second); err == nil || !strings.Contains(err.Error(), "tls to proxy") {
		t.Fatalf("an untrusted proxy certificate must fail: %v", err)
	}
	pool, _ := pki.CertPoolFromPEM(ca.CertPEM())
	netx.SetProxyRootCAs(t, pool)
	c, err := netx.Dial(context.Background(), addr, p.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c, "over tls"); got != "over tls" {
		t.Fatalf("got %q", got)
	}
}

func TestDialProxyRefusals(t *testing.T) {
	addr := echoServer(t)
	_, port, _ := net.SplitHostPort(addr)
	for name, c := range map[string]struct {
		o    proxytest.Options
		user *url.Userinfo
		want string
	}{
		"no credentials":    {proxytest.Options{User: "u", Password: "p"}, nil, "407 Proxy Authentication Required (set user:password in edge.proxy)"},
		"wrong credentials": {proxytest.Options{User: "u", Password: "p"}, url.UserPassword("u", "x"), "407"},
		"port not allowed":  {proxytest.Options{AllowPorts: []string{"443"}}, nil, "CONNECT refused: 403 Forbidden"},
		"other status":      {proxytest.Options{Status: 502}, nil, "CONNECT refused: 502 Bad Gateway"},
		"port allowed":      {proxytest.Options{AllowPorts: []string{port}}, nil, ""},
	} {
		p := proxytest.Start(t, c.o)
		u := *p.URL
		u.User = c.user
		conn, err := netx.Dial(context.Background(), addr, &u, time.Second)
		if c.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			_ = conn.Close()
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want %q", name, err, c.want)
		}
		if strings.Contains(c.want, "407") != errors.Is(err, netx.ErrProxyAuth) {
			t.Fatalf("%s: errors.Is(ErrProxyAuth) wrong for %v", name, err)
		}
	}
}

func TestDialProxyTimeoutsAndFailures(t *testing.T) {
	addr := echoServer(t)
	silent := proxytest.Start(t, proxytest.Options{NoAnswer: true})
	start := time.Now()
	_, err := netx.Dial(context.Background(), addr, silent.URL, 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no answer to CONNECT within 200ms") {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the timeout took %v", d)
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, err := netx.Dial(ctx, addr, silent.URL, 5*time.Second); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("a cancelled dial: %v", err)
	}

	// Nothing listens there (port 1, so that no other test can hold it
	// meanwhile): the proxy cannot be reached.
	gone := "127.0.0.1:1"
	if _, err := netx.Dial(context.Background(), addr, &url.URL{Scheme: "http", Host: gone}, time.Second); err == nil || !strings.Contains(err.Error(), "dial proxy") {
		t.Fatalf("got %v", err)
	}

	// The upstream is down: the proxy answers 502.
	dead := proxytest.Start(t, proxytest.Options{})
	if _, err := netx.Dial(context.Background(), gone, dead.URL, time.Second); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("got %v", err)
	}
}

// The test proxy answers anything but CONNECT with 405.
func TestProxyRefusesOtherMethods(t *testing.T) {
	p := proxytest.Start(t, proxytest.Options{})
	c, err := net.Dial("tcp", p.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET http://example/ HTTP/1.1\r\nHost: example\r\n\r\n")
	b := make([]byte, 12)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "HTTP/1.1 405" {
		t.Fatalf("got %q %v", b, err)
	}
}
