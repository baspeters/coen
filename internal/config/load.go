package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/baspeters/coen/internal/route"
	"gopkg.in/yaml.v3"
)

func LoadEdge(path string) (*EdgeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c EdgeConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	origins := make([]string, len(c.Routes))
	base := filepath.Base(path)
	for i := range origins {
		origins[i] = base
	}
	extra, extraOrigins, err := readEdgeDropIns(path)
	if err != nil {
		return nil, err
	}
	c.Routes = append(c.Routes, extra...)
	origins = append(origins, extraOrigins...)

	if c.Ingress.ReadHeaderTimeout == 0 {
		c.Ingress.ReadHeaderTimeout = Duration(10 * time.Second)
	}
	if c.Drain == 0 {
		c.Drain = Duration(15 * time.Second)
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	hosts := make([]sourced, len(c.Routes))
	for i, r := range c.Routes {
		hosts[i] = sourced{host: r.Host, origin: origins[i]}
	}
	if err := checkDuplicateHosts(hosts); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *EdgeConfig) Validate() error {
	switch c.Ingress.Mode {
	case "standalone":
		if c.Ingress.TLS.Cert == "" || c.Ingress.TLS.Key == "" {
			return fmt.Errorf("ingress.tls.cert and ingress.tls.key are required in standalone mode")
		}
	case "proxied":
		// no public cert needed
	default:
		return fmt.Errorf("ingress.mode must be 'standalone' or 'proxied', got %q", c.Ingress.Mode)
	}
	if c.Ingress.Listen == "" {
		return fmt.Errorf("ingress.listen is required")
	}
	for name, v := range map[string]string{"tunnel.listen": c.Tunnel.Listen, "tunnel.ca": c.Tunnel.CA, "tunnel.cert": c.Tunnel.Cert, "tunnel.key": c.Tunnel.Key} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	for i, r := range c.Routes {
		if r.Host == "" {
			return fmt.Errorf("route %d: host is required", i)
		}
		if r.AgentFingerprint == "" {
			return fmt.Errorf("route %q: agent_fingerprint is required", r.Host)
		}
		if err := route.ValidatePattern(r.Host); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
	}
	return nil
}

func LoadAgent(path string) (*AgentConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c AgentConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	origins := make([]string, len(c.Routes))
	base := filepath.Base(path)
	for i := range origins {
		origins[i] = base
	}
	extra, extraOrigins, err := readAgentDropIns(path)
	if err != nil {
		return nil, err
	}
	c.Routes = append(c.Routes, extra...)
	origins = append(origins, extraOrigins...)

	if c.Reconnect.MinBackoff == 0 {
		c.Reconnect.MinBackoff = Duration(time.Second)
	}
	if c.Reconnect.MaxBackoff == 0 {
		c.Reconnect.MaxBackoff = Duration(30 * time.Second)
	}
	if c.Drain == 0 {
		c.Drain = Duration(15 * time.Second)
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	hosts := make([]sourced, len(c.Routes))
	for i, r := range c.Routes {
		hosts[i] = sourced{host: r.Host, origin: origins[i]}
	}
	if err := checkDuplicateHosts(hosts); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *AgentConfig) Validate() error {
	for name, v := range map[string]string{"edge.address": c.Edge.Address, "edge.ca": c.Edge.CA, "edge.cert": c.Edge.Cert, "edge.key": c.Edge.Key} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	for i, r := range c.Routes {
		if r.Host == "" {
			return fmt.Errorf("route %d: host is required", i)
		}
		if r.Service == "" {
			return fmt.Errorf("route %q: service is required", r.Host)
		}
		if err := route.ValidatePattern(r.Host); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
	}
	return nil
}
