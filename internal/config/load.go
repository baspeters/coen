package config

import (
	"fmt"
	"os"
	"time"

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
	if err := c.Validate(); err != nil {
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
	if c.Reconnect.MinBackoff == 0 {
		c.Reconnect.MinBackoff = Duration(time.Second)
	}
	if c.Reconnect.MaxBackoff == 0 {
		c.Reconnect.MaxBackoff = Duration(30 * time.Second)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *AgentConfig) Validate() error {
	for name, v := range map[string]string{"edge.address": c.Edge.Address, "edge.ca": c.Edge.CA, "edge.cert": c.Edge.Cert, "edge.key": c.Edge.Key, "service.address": c.Service.Address} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}
