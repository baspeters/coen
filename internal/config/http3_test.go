package config

import (
	"strings"
	"testing"
)

func standaloneEdge() EdgeConfig {
	c := validEdgeConfig()
	c.Ingress.Mode = "standalone"
	c.Ingress.Listen = ":443"
	c.Ingress.TLS = TLSFiles{Cert: "/p.crt", Key: "/p.key"}
	return c
}

func TestHTTP3Validation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*EdgeConfig)
		err  string // "" for valid
	}{
		{"off", func(c *EdgeConfig) {}, ""},
		{"on, defaults", func(c *EdgeConfig) { c.Ingress.HTTP3.Enabled = true }, ""},
		{"own udp port", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, Listen: "0.0.0.0:8443"} }, ""},
		{"alt_svc off", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: "off"} }, ""},
		{"alt_svc custom", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: `h3=":443"; ma=3600`} }, ""},
		{"proxied", func(c *EdgeConfig) { c.Ingress.Mode = "proxied"; c.Ingress.HTTP3.Enabled = true }, "needs ingress.mode standalone"},
		{"bad listen", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, Listen: "nope"} }, "ingress.http3.listen"},
		{"port 0", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, Listen: ":0"} }, "ingress.http3.listen"},
		{"bad ingress.listen, shared", func(c *EdgeConfig) { c.Ingress.Listen = "edge:443x"; c.Ingress.HTTP3.Enabled = true }, "ingress.listen (HTTP/3 listens there too)"},
		{"multi-line alt_svc", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: "a\r\nX: y"} }, "alt_svc"},
		{"control byte in alt_svc", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: "h3=\":443\"\x00"} }, "alt_svc"},
		{"blank alt_svc", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: "  "} }, "alt_svc"},
		{"off, settings kept", func(c *EdgeConfig) { c.Ingress.HTTP3 = HTTP3Config{Listen: ":8443", AltSvc: "nonsense\r\n"} }, ""},
	}
	for _, tc := range cases {
		c := standaloneEdge()
		tc.edit(&c)
		err := c.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: error %v, want one mentioning %q", tc.name, err, tc.err)
		}
	}
}

func TestHTTP3Listen(t *testing.T) {
	c := standaloneEdge()
	if c.Ingress.HTTP3Listen() != ":443" {
		t.Fatal("HTTP/3 listens on ingress.listen by default")
	}
	c.Ingress.HTTP3.Listen = "[::]:8443"
	if c.Ingress.HTTP3Listen() != "[::]:8443" {
		t.Fatal("HTTP3Listen ignores its own listen")
	}
	if c.Ingress.AltSvcHeaderFor(8443) != "" {
		t.Fatal("HTTP/3 off: no advertisement")
	}
	c.Ingress.HTTP3 = HTTP3Config{Enabled: true, AltSvc: "OFF"}
	if c.Ingress.AltSvcHeaderFor(443) != "" {
		t.Fatal("alt_svc: off, in any case")
	}
}

func TestAltSvcHeaderFor(t *testing.T) {
	c := standaloneEdge()
	c.Ingress.HTTP3.Enabled = true
	if got := c.Ingress.AltSvcHeaderFor(8443); got != `h3=":8443"; ma=86400` {
		t.Fatalf("auto on the served port: %q", got)
	}
	if got := c.Ingress.AltSvcHeaderFor(0); got != "" {
		t.Fatalf("no port, no advertisement: %q", got)
	}
	c.Ingress.HTTP3.AltSvc = `h3=":443"`
	if got := c.Ingress.AltSvcHeaderFor(8443); got != `h3=":443"` {
		t.Fatalf("a literal value is sent as given: %q", got)
	}
}
