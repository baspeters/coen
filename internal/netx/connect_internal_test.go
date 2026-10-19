package netx

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A proxy URL without a port uses the scheme's.
func TestDialProxyDefaultPorts(t *testing.T) {
	for scheme, port := range map[string]string{"http": ":80", "https": ":443"} {
		// Nothing listens on these on a loopback test address; the dial
		// error names the address tried.
		_, err := Dial(context.Background(), "edge:443", &url.URL{Scheme: scheme, Host: "127.0.0.2"}, 500*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "127.0.0.2"+port) {
			t.Fatalf("%s: got %v", scheme, err)
		}
	}
}

// A proxy connection that breaks before the CONNECT is sent or answered.
func TestConnectBrokenConnection(t *testing.T) {
	a, b := net.Pipe()
	_ = b.Close()
	if _, err := connect(a, "edge:443", &url.URL{Scheme: "http", Host: "p"}); err == nil || !strings.Contains(err.Error(), "send CONNECT") {
		t.Fatalf("got %v", err)
	}
	c, d := net.Pipe()
	go func() {
		buf := make([]byte, 512)
		_, _ = d.Read(buf)
		_, _ = d.Write([]byte("not http\r\n\r\n"))
		_ = d.Close()
	}()
	if _, err := connect(c, "edge:443", &url.URL{Scheme: "http", Host: "p"}); err == nil || !strings.Contains(err.Error(), "read CONNECT answer") {
		t.Fatalf("got %v", err)
	}
}
