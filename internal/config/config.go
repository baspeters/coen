package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from YAML strings like "30s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type AdminConfig struct {
	Socket string `yaml:"socket"`
}

type TLSFiles struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type IngressConfig struct {
	Mode   string   `yaml:"mode"`
	Listen string   `yaml:"listen"`
	TLS    TLSFiles `yaml:"tls"`
}

type TunnelServerConfig struct {
	Listen                   string   `yaml:"listen"`
	CA                       string   `yaml:"ca"`
	Cert                     string   `yaml:"cert"`
	Key                      string   `yaml:"key"`
	AllowedAgentFingerprints []string `yaml:"allowed_agent_fingerprints"`
}

type EdgeConfig struct {
	Ingress IngressConfig      `yaml:"ingress"`
	Tunnel  TunnelServerConfig `yaml:"tunnel"`
	Log     LogConfig          `yaml:"log"`
	Admin   AdminConfig        `yaml:"admin"`
}

type EdgeRef struct {
	Address         string `yaml:"address"`
	CA              string `yaml:"ca"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	EdgeFingerprint string `yaml:"edge_fingerprint"`
}

type ServiceConfig struct {
	Address string `yaml:"address"`
}

type ReconnectConfig struct {
	MinBackoff Duration `yaml:"min_backoff"`
	MaxBackoff Duration `yaml:"max_backoff"`
}

type AgentConfig struct {
	Edge      EdgeRef         `yaml:"edge"`
	Service   ServiceConfig   `yaml:"service"`
	Reconnect ReconnectConfig `yaml:"reconnect"`
	Log       LogConfig       `yaml:"log"`
	Admin     AdminConfig     `yaml:"admin"`
}
