package netx

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/baspeters/coen/internal/proxy"
)

// Dial connects to addr (host:port) over TCP, or, when via is set, through
// that HTTP proxy with CONNECT: the returned connection is then a byte stream
// to addr through the proxy, ready for the caller's own TLS. via is an
// http:// or https:// URL, optionally with user:password for Basic
// authentication. timeout bounds the dial, any TLS to the proxy, and the
// proxy's answer.
func Dial(ctx context.Context, addr string, via *url.URL, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	if via == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	proxyAddr := via.Host
	if via.Port() == "" {
		port := "80"
		if via.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(via.Hostname(), port)
	}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if via.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: via.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: proxyRootCAs})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls to proxy %s: %w", proxyAddr, err)
		}
		conn = tc
	}
	// The CONNECT exchange is bounded by the context: closing the
	// connection ends a write or read still waiting when it expires.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	tunnel, err := connect(conn, addr, via)
	if !stop() {
		_ = conn.Close()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("proxy %s: no answer to CONNECT within %s", proxyAddr, timeout)
		}
		return nil, ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s: %w", proxyAddr, err)
	}
	return tunnel, nil
}

// ErrProxyAuth reports a proxy that refused CONNECT for want of (valid)
// credentials.
var ErrProxyAuth = errors.New("CONNECT refused: 407 Proxy Authentication Required (set user:password in edge.proxy)")

// proxyRootCAs verifies an https:// proxy's certificate; nil means the
// system's roots. Tests set it.
var proxyRootCAs *x509.CertPool

// connect asks the proxy on conn for a tunnel to addr and returns the
// connection to use from then on.
func connect(conn net.Conn, addr string, via *url.URL) (net.Conn, error) {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u := via.User; u != nil {
		pass, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)) + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("read CONNECT answer: %w", err)
	}
	_ = resp.Body.Close() // a 2xx to CONNECT has no body; it is the tunnel
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == http.StatusProxyAuthRequired {
			return nil, ErrProxyAuth
		}
		return nil, fmt.Errorf("CONNECT refused: %s", resp.Status)
	}
	if n := br.Buffered(); n > 0 {
		// The proxy sent tunnel bytes right after its answer: keep them.
		peeked, _ := br.Peek(n)
		return proxy.WithPrefix(conn, append([]byte(nil), peeked...)), nil
	}
	return conn, nil
}
