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

// MetricsConfig enables the Prometheus /metrics endpoint. It is off when Listen
// is empty.
type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

type TLSFiles struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type IngressConfig struct {
	Mode              string   `yaml:"mode"`
	Listen            string   `yaml:"listen"`
	TLS               TLSFiles `yaml:"tls"`
	MaxConnections    int      `yaml:"max_connections"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	IdleTimeout       Duration `yaml:"idle_timeout"`
}

// EdgeRoute maps a host pattern to the agent(s) (by client-cert fingerprint)
// that serve it. Host ownership is edge-authoritative.
//
// A route names one agent with AgentFingerprint, or several with
// AgentFingerprints, and the edge balances connections across every live
// session among them. AllowSharedCert lets several agents run with the same
// certificate, so one fingerprint can have several live sessions; without it,
// a second connection with a fingerprint that is already live is refused.
type EdgeRoute struct {
	Host              string   `yaml:"host"`
	AgentFingerprint  string   `yaml:"agent_fingerprint"`
	AgentFingerprints []string `yaml:"agent_fingerprints"`
	Balance           string   `yaml:"balance"`
	AllowSharedCert   bool     `yaml:"allow_shared_cert"`
	MaxConnections    int      `yaml:"max_connections"`
}

// Balancing algorithms for EdgeRoute.Balance.
const (
	BalanceLeastConn  = "least_conn"  // the session with the fewest open streams (default)
	BalanceRoundRobin = "round_robin" // each session in turn
)

// Fingerprints returns the route's agent fingerprints, whichever field set them.
func (r EdgeRoute) Fingerprints() []string {
	if r.AgentFingerprint != "" {
		return []string{r.AgentFingerprint}
	}
	return r.AgentFingerprints
}

// BalanceMode returns the route's balancing algorithm, defaulting to least_conn.
func (r EdgeRoute) BalanceMode() string {
	if r.Balance == "" {
		return BalanceLeastConn
	}
	return r.Balance
}

// AgentRoute maps a host pattern to a local backend service address.
type AgentRoute struct {
	Host    string `yaml:"host"`
	Service string `yaml:"service"`
}

type TunnelServerConfig struct {
	Listen string `yaml:"listen"`
	CA     string `yaml:"ca"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

type EdgeConfig struct {
	Ingress IngressConfig      `yaml:"ingress"`
	Tunnel  TunnelServerConfig `yaml:"tunnel"`
	Routes  []EdgeRoute        `yaml:"routes"`
	Drain   Duration           `yaml:"drain_timeout"`
	Log     LogConfig          `yaml:"log"`
	Admin   AdminConfig        `yaml:"admin"`
	Metrics MetricsConfig      `yaml:"metrics"`
	// Version is the build version, set programmatically (not from YAML). The
	// edge stamps it into each stream preamble for agent-side skew detection.
	Version string `yaml:"-"`
}

// AllowedFingerprints derives the set of agent fingerprints permitted to connect
// from the configured routes.
func (c *EdgeConfig) AllowedFingerprints() map[string]bool {
	m := make(map[string]bool, len(c.Routes))
	for _, r := range c.Routes {
		for _, fp := range r.Fingerprints() {
			m[fp] = true
		}
	}
	return m
}

// SharedFingerprints returns the fingerprints whose routes allow several live
// sessions (allow_shared_cert). Validation guarantees a fingerprint is either
// shared on every route that names it or on none.
func (c *EdgeConfig) SharedFingerprints() map[string]bool {
	m := make(map[string]bool)
	for _, r := range c.Routes {
		if r.AllowSharedCert {
			for _, fp := range r.Fingerprints() {
				m[fp] = true
			}
		}
	}
	return m
}

type EdgeRef struct {
	Address         string `yaml:"address"`
	CA              string `yaml:"ca"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	EdgeFingerprint string `yaml:"edge_fingerprint"`
}

type ReconnectConfig struct {
	MinBackoff Duration `yaml:"min_backoff"`
	MaxBackoff Duration `yaml:"max_backoff"`
}

type AgentConfig struct {
	Edge      EdgeRef         `yaml:"edge"`
	Routes    []AgentRoute    `yaml:"routes"`
	Reconnect ReconnectConfig `yaml:"reconnect"`
	Drain     Duration        `yaml:"drain_timeout"`
	Log       LogConfig       `yaml:"log"`
	Admin     AdminConfig     `yaml:"admin"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	// Version is the build version, set programmatically (not from YAML), used
	// to warn on an edge/agent version skew.
	Version string `yaml:"-"`
}
