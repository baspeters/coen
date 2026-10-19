// Package proxytest runs a small HTTP CONNECT proxy for tests.
package proxytest

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// Options shape the proxy's behaviour.
type Options struct {
	User, Password string           // when set, Basic credentials are required
	AllowPorts     []string         // when set, CONNECT only to these ports, else 403 (like squid's SSL_ports)
	TLS            *tls.Certificate // serve https:// instead of http://
	Status         int              // answer every CONNECT with this status instead
	NoAnswer       bool             // read the CONNECT and never answer
	EarlyBytes     string           // tunnel bytes sent in the same write as the 200
}

// Proxy is a running CONNECT proxy.
type Proxy struct {
	URL *url.URL // with the credentials from Options

	mu      sync.Mutex
	targets []string
}

// Targets returns the addresses CONNECTed to, in order.
func (p *Proxy) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// Start runs a proxy until the test ends.
func Start(t testing.TB, o Options) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if o.TLS != nil {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*o.TLS}})
		scheme = "https"
	}
	p := &Proxy{URL: &url.URL{Scheme: scheme, Host: ln.Addr().String()}}
	if o.User != "" {
		p.URL.User = url.UserPassword(o.User, o.Password)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); p.serve(c, o) }()
		}
	}()
	return p
}

func (p *Proxy) serve(c net.Conn, o Options) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	answer := func(code int) { _, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n\r\n", code, http.StatusText(code)) }
	switch {
	case o.NoAnswer:
		_, _ = io.Copy(io.Discard, br)
		return
	case req.Method != http.MethodConnect:
		answer(http.StatusMethodNotAllowed)
		return
	case o.User != "" && req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(o.User+":"+o.Password)):
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\n\r\n")
		return
	case o.Status != 0:
		answer(o.Status)
		return
	}
	if len(o.AllowPorts) > 0 {
		_, port, _ := net.SplitHostPort(req.Host)
		allowed := false
		for _, a := range o.AllowPorts {
			allowed = allowed || a == port
		}
		if !allowed {
			answer(http.StatusForbidden)
			return
		}
	}
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		answer(http.StatusBadGateway)
		return
	}
	defer up.Close()
	if o.EarlyBytes != "" {
		// The 200 and the first tunnel bytes in one write, so a client
		// reading the answer buffers some of the tunnel too.
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"+o.EarlyBytes)
	} else {
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	}
	// As a proxy like squid does, the tunnel ends when either side closes
	// (the deferred closes end the other copy).
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
