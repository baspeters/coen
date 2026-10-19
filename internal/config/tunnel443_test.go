package config

import (
	"strings"
	"testing"
	"time"
)

func TestShareIngressValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*EdgeConfig)
		err  string // "" for valid
	}{
		{"shared, own listener too", func(c *EdgeConfig) { c.Tunnel.ShareIngress = true }, ""},
		{"shared, no own listener", func(c *EdgeConfig) { c.Tunnel.ShareIngress = true; c.Tunnel.Listen = "" }, ""},
		{"not shared, no listener", func(c *EdgeConfig) { c.Tunnel.Listen = "" }, "tunnel.listen is required"},
		{"shared still needs the PKI", func(c *EdgeConfig) { c.Tunnel.ShareIngress = true; c.Tunnel.CA = "" }, "tunnel.ca is required"},
		{"proxied", func(c *EdgeConfig) {
			c.Ingress.Mode = "proxied"
			c.Ingress.TLS = TLSFiles{}
			c.Tunnel.ShareIngress = true
		}, "tunnel.share_ingress needs ingress.mode standalone"},
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

func TestEdgeProxyValidation(t *testing.T) {
	cases := []struct {
		proxy string
		err   string // "" for valid
	}{
		{"", ""},
		{"http://proxy.corp:3128", ""},
		{"http://proxy.corp", ""},
		{"https://proxy.corp:443/", ""},
		{"http://agent:s%3Acret@10.0.0.1:8080", ""},
		{"socks5://proxy:1080", `not scheme "socks5"`},
		{"proxy.corp:3128", `not scheme "proxy.corp"`},
		{"http://", "names no host"},
		{"http://proxy:3128/path", "nothing after the host"},
		{"http://proxy:3128/?a=1", "nothing after the host"},
		{"http://proxy:0", "is not 1 to 65535"},
		{"http://proxy:99999", "is not 1 to 65535"},
		{"http://%zz", "does not parse"},
	}
	for _, tc := range cases {
		c := validAgentConfig()
		c.Edge.Proxy = tc.proxy
		err := c.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%q: unexpected error %v", tc.proxy, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%q: error %v, want one mentioning %q", tc.proxy, err, tc.err)
		}
	}
	c := validAgentConfig()
	if c.Edge.ProxyURL() != nil {
		t.Fatal("no proxy: nil URL")
	}
	c.Edge.Proxy = "http://u:p@proxy:3128"
	if u := c.Edge.ProxyURL(); u == nil || u.Host != "proxy:3128" || u.User.Username() != "u" {
		t.Fatalf("got %v", u)
	}
	c.Edge.Proxy = "http://%zz"
	if c.Edge.ProxyURL() != nil {
		t.Fatal("an unparsable proxy: nil URL")
	}
}

func TestAgentWaitValidation(t *testing.T) {
	c := standaloneEdge()
	c.AgentWait = NewDuration(-time.Second)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "agent_wait must not be negative") {
		t.Fatalf("got %v", err)
	}
	c.AgentWait = NewDuration(0)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
