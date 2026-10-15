package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/baspeters/coen/internal/route"
)

func LoadEdge(path string) (*EdgeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c EdgeConfig
	if err := strictDecode(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	routes, origins, err := loadRoutes(path, c.Routes)
	if err != nil {
		return nil, err
	}
	c.Routes = routes

	if c.Ingress.ReadHeaderTimeout == 0 {
		c.Ingress.ReadHeaderTimeout = Duration(10 * time.Second)
	}
	if c.Drain == 0 {
		c.Drain = Duration(15 * time.Second)
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := checkRouteHosts(c.Routes, origins, func(r EdgeRoute) string { return r.Host }); err != nil {
		return nil, err
	}
	return &c, nil
}

// loadRoutes returns the base routes plus any drop-in routes, with a parallel
// list of origin labels used for duplicate-host error messages.
func loadRoutes[R any](path string, base []R) ([]R, []string, error) {
	origins := make([]string, len(base))
	label := filepath.Base(path)
	for i := range origins {
		origins[i] = label
	}
	extra, extraOrigins, err := readDropIns[R](path)
	if err != nil {
		return nil, nil, err
	}
	return append(base, extra...), append(origins, extraOrigins...), nil
}

// checkRouteHosts fails if any route host (base or drop-in) appears twice.
func checkRouteHosts[R any](routes []R, origins []string, hostOf func(R) string) error {
	hosts := make([]sourced, len(routes))
	for i, r := range routes {
		hosts[i] = sourced{host: hostOf(r), origin: origins[i]}
	}
	return checkDuplicateHosts(hosts)
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
	if err := c.Ingress.validateHTTP3(); err != nil {
		return err
	}
	for name, v := range map[string]string{"tunnel.listen": c.Tunnel.Listen, "tunnel.ca": c.Tunnel.CA, "tunnel.cert": c.Tunnel.Cert, "tunnel.key": c.Tunnel.Key} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if err := c.Metrics.validate(); err != nil {
		return err
	}
	// A fixed order, so a metrics address that overlaps both is always
	// reported against the same one.
	for _, l := range []struct{ name, addr string }{{"tunnel.listen", c.Tunnel.Listen}, {"ingress.listen", c.Ingress.Listen}} {
		if c.Metrics.Listen != "" && ListenersOverlap(c.Metrics.Listen, l.addr) {
			return fmt.Errorf("metrics.listen %q conflicts with %s %q", c.Metrics.Listen, l.name, l.addr)
		}
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	sharedBy := map[string]string{}  // fingerprint -> a route that shares it
	exclusive := map[string]string{} // fingerprint -> a route that does not
	for i, r := range c.Routes {
		if r.Host == "" {
			return fmt.Errorf("route %d: host is required", i)
		}
		if err := route.ValidatePattern(r.Host); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		if err := r.validateAgents(); err != nil {
			return fmt.Errorf("route %q: %w", r.Host, err)
		}
		for _, fp := range r.Fingerprints() {
			if r.AllowSharedCert {
				sharedBy[fp] = r.Host
			} else {
				exclusive[fp] = r.Host
			}
		}
	}
	// Sharing is a property of the certificate, not of one route: a
	// fingerprint shared on one route but exclusive on another would make the
	// duplicate guard depend on which route a connection happens to serve.
	// A second pass in config order keeps the error stable when several
	// fingerprints conflict.
	for _, r := range c.Routes {
		for _, fp := range r.Fingerprints() {
			shared, isShared := sharedBy[fp]
			other, isExclusive := exclusive[fp]
			if isShared && isExclusive {
				return fmt.Errorf("agent fingerprint %s has allow_shared_cert on route %q but not on route %q; set it on every route that names it, or on none", fp, shared, other)
			}
		}
	}
	return nil
}

// validateAgents checks the route names its agents in exactly one way, with no
// empty or repeated fingerprint, and a known balancing algorithm.
func (r EdgeRoute) validateAgents() error {
	switch {
	case r.AgentFingerprint != "" && len(r.AgentFingerprints) > 0:
		return fmt.Errorf("set agent_fingerprint or agent_fingerprints, not both")
	case r.AgentFingerprint == "" && len(r.AgentFingerprints) == 0:
		return fmt.Errorf("agent_fingerprint or agent_fingerprints is required")
	}
	seen := map[string]bool{}
	for _, fp := range r.AgentFingerprints {
		if fp == "" {
			return fmt.Errorf("agent_fingerprints has an empty entry")
		}
		if seen[fp] {
			return fmt.Errorf("agent_fingerprints lists %s twice", fp)
		}
		seen[fp] = true
	}
	switch r.Balance {
	case "", BalanceLeastConn, BalanceRoundRobin:
		return nil
	default:
		return fmt.Errorf("balance must be %q or %q, got %q", BalanceLeastConn, BalanceRoundRobin, r.Balance)
	}
}

func LoadAgent(path string) (*AgentConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c AgentConfig
	if err := strictDecode(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	routes, origins, err := loadRoutes(path, c.Routes)
	if err != nil {
		return nil, err
	}
	c.Routes = routes

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
	if err := checkRouteHosts(c.Routes, origins, func(r AgentRoute) string { return r.Host }); err != nil {
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
	if err := c.Metrics.validate(); err != nil {
		return err
	}
	if c.Metrics.Listen != "" {
		// The agent's metrics endpoint must not sit on a backend's address:
		// whichever binds first wins, and if the agent does, public requests
		// for that host reach its unauthenticated /metrics.
		local := localIPs()
		for _, r := range c.Routes {
			if serviceOnMetricsSocket(c.Metrics.Listen, r.Service, local) {
				return fmt.Errorf("metrics.listen %q conflicts with the service %q of route %q", c.Metrics.Listen, r.Service, r.Host)
			}
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

// validate checks metrics.listen is host:port with a numeric port when it is set.
func (m MetricsConfig) validate() error {
	if m.Listen == "" {
		return nil
	}
	if _, _, err := SplitListen(m.Listen); err != nil {
		return fmt.Errorf("metrics.listen %q must be host:port with a port from 1 to 65535 or a service name, for example 127.0.0.1:9464", m.Listen)
	}
	return nil
}

// validateHTTP3 checks the ingress.http3 block: HTTP/3 needs the edge to
// terminate TLS itself (standalone mode), a usable UDP address, and an
// Alt-Svc value that is a single header line.
func (i IngressConfig) validateHTTP3() error {
	h := i.HTTP3
	if !h.Enabled {
		return nil // the other settings are kept but unused, so HTTP/3 can be switched off by enabled alone
	}
	if i.Mode != "standalone" {
		return fmt.Errorf("ingress.http3 needs ingress.mode standalone; behind a reverse proxy, let the proxy serve HTTP/3")
	}
	if _, _, err := SplitListenNet("udp", i.HTTP3Listen()); err != nil {
		name := "ingress.http3.listen"
		if h.Listen == "" {
			name = "ingress.listen (HTTP/3 listens there too)"
		}
		return fmt.Errorf("%s %q must be host:port with a port from 1 to 65535 or a service name", name, i.HTTP3Listen())
	}
	switch strings.ToLower(h.AltSvc) {
	case "", AltSvcAuto, AltSvcOff:
		return nil
	}
	if !httpguts.ValidHeaderFieldValue(h.AltSvc) || strings.TrimSpace(h.AltSvc) == "" {
		return fmt.Errorf("ingress.http3.alt_svc must be auto, off, or a single-line header value")
	}
	return nil
}

// SplitListen splits a listen address into host and port, resolving a named
// port (":https") the way net.Listen does. Port 0 is rejected: a fixed address
// is needed for something other processes connect to.
func SplitListen(addr string) (host string, port int, err error) {
	return SplitListenNet("tcp", addr)
}

// SplitListenNet is SplitListen for a listener on network ("tcp" or "udp"),
// which decides how a named port resolves.
func SplitListenNet(network, addr string) (host string, port int, err error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = net.LookupPort(network, p)
	if err != nil || port < 1 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return host, port, nil
}

// IsWildcardHost reports whether a listen host binds every local address: empty,
// 0.0.0.0, or :: (and their equivalent spellings). Go opens a dual-stack socket
// for any of them, so each covers both IPv4 and IPv6.
func IsWildcardHost(h string) bool {
	if h == "" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

// LoopbackHosts returns the addresses a client on this host can use to reach a
// listener bound to host: both loopbacks for a wildcard, else the host itself.
func LoopbackHosts(host string) []string {
	if IsWildcardHost(host) {
		return []string{"127.0.0.1", "::1"}
	}
	return []string{host}
}

// hostIPs returns the addresses a host stands for without any network lookup:
// an IP literal is itself and "localhost" is the loopback addresses. Any other
// hostname is unknown (ok false) and is compared as written: config loading
// must not depend on DNS, which may not be up yet at boot and would make the
// same file pass or fail depending on when it is read.
func hostIPs(host string) ([]net.IP, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, true
	}
	if strings.EqualFold(host, "localhost") {
		return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, true
	}
	return nil, false
}

// endpoint is a parsed address: its port, its host, and the IPs it stands for.
type endpoint struct {
	host     string
	port     int
	wildcard bool     // empty, 0.0.0.0, or ::: a dual-stack listener on every address
	ips      []net.IP // the host's IPs; empty for a wildcard
	resolved bool     // ips are known (an IP literal or localhost; see hostIPs)
}

func parseEndpoint(addr string) (endpoint, bool) {
	host, port, err := SplitListen(addr)
	if err != nil {
		return endpoint{}, false
	}
	e := endpoint{host: host, port: port, wildcard: IsWildcardHost(host)}
	if !e.wildcard {
		e.ips, e.resolved = hostIPs(host)
	}
	return e, true
}

// overlaps reports whether a listener at e and one at o (or a dial to o)
// meet on the same socket: the same port, and a wildcard on either side or a
// shared IP. A hostname other than localhost is compared as written.
func (e endpoint) overlaps(o endpoint) bool {
	if e.port != o.port {
		return false
	}
	if e.wildcard || o.wildcard {
		return true
	}
	if !e.resolved || !o.resolved {
		return strings.EqualFold(e.host, o.host)
	}
	for _, x := range e.ips {
		for _, y := range o.ips {
			if x.Equal(y) {
				return true
			}
		}
	}
	return false
}

// ListenersOverlap reports whether two listen addresses would compete for the
// same socket. A wildcard host (empty, 0.0.0.0, or ::) overlaps anything,
// since Go listens dual-stack on all of them; localhost is the loopback
// addresses; other hostnames are compared as written (see hostIPs).
// Unparsable addresses never overlap here; they fail elsewhere.
func ListenersOverlap(a, b string) bool {
	ea, okA := parseEndpoint(a)
	eb, okB := parseEndpoint(b)
	return okA && okB && ea.overlaps(eb)
}

// EdgeLogLevel and AgentLogLevel read log.level from a config file without
// validating the rest, for a runtime log-level reload. The file is still
// decoded strictly as its role's type; the caller parses the level itself.
func EdgeLogLevel(path string) (string, error) { return readLogLevel(path, &EdgeConfig{}) }

func AgentLogLevel(path string) (string, error) { return readLogLevel(path, &AgentConfig{}) }

// EdgeAdminSocket and AgentAdminSocket read admin.socket the same way, for
// `coen status`, which only needs the socket path to reach a running daemon.
func EdgeAdminSocket(path string) (string, error) { return readAdminSocket(path, &EdgeConfig{}) }

func AgentAdminSocket(path string) (string, error) { return readAdminSocket(path, &AgentConfig{}) }

// roleConfig is a role config read for one setting without full validation.
type roleConfig interface {
	logConfig() LogConfig
	adminConfig() AdminConfig
}

func (c *EdgeConfig) logConfig() LogConfig      { return c.Log }
func (c *AgentConfig) logConfig() LogConfig     { return c.Log }
func (c *EdgeConfig) adminConfig() AdminConfig  { return c.Admin }
func (c *AgentConfig) adminConfig() AdminConfig { return c.Admin }

func readLogLevel(path string, c roleConfig) (string, error) {
	if err := strictDecodeFile(path, c); err != nil {
		return "", err
	}
	return c.logConfig().Level, nil
}

func readAdminSocket(path string, c roleConfig) (string, error) {
	if err := strictDecodeFile(path, c); err != nil {
		return "", err
	}
	return c.adminConfig().Socket, nil
}

// interfaceAddrs lists this host's addresses; a variable so tests can stub it.
var interfaceAddrs = net.InterfaceAddrs

// serviceOnMetricsSocket reports whether a route's service (an address the
// agent dials) would be answered by the agent's own metrics listener. A dial
// to an empty or unspecified host reaches this machine's loopback, so it is
// modelled as the loopback addresses. Only the service addresses on this host
// (loopback or a local interface address) can collide; a remote backend, or a
// hostname other than localhost (not looked up; see hostIPs), never does.
func serviceOnMetricsSocket(metricsAddr, service string, local func(net.IP) bool) bool {
	m, okM := parseEndpoint(metricsAddr)
	svc, okS := parseEndpoint(service)
	if !okM || !okS {
		return false
	}
	if svc.wildcard {
		svc = endpoint{host: svc.host, port: svc.port, ips: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, resolved: true}
	}
	if !svc.resolved {
		return false
	}
	onHost := svc.ips[:0:0]
	for _, ip := range svc.ips {
		if ip.IsLoopback() || local(ip) {
			onHost = append(onHost, ip)
		}
	}
	if len(onHost) == 0 {
		return false
	}
	svc.ips = onHost
	return m.overlaps(svc)
}

// localIPs returns a membership test for this host's interface addresses.
func localIPs() func(net.IP) bool {
	addrs, err := interfaceAddrs()
	if err != nil {
		return func(net.IP) bool { return false }
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return func(ip net.IP) bool {
		for _, l := range ips {
			if l.Equal(ip) {
				return true
			}
		}
		return false
	}
}
