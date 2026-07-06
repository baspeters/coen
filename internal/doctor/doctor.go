package doctor

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/baspeters/coen/internal/admin"
	"github.com/baspeters/coen/internal/config"
	"github.com/baspeters/coen/internal/pki"
	"github.com/baspeters/coen/internal/tunnel"
)

type Result struct {
	Name   string
	OK     bool
	Detail string
	Hint   string
}

func ok(name, detail string) Result { return Result{Name: name, OK: true, Detail: detail} }
func fail(name, detail, hint string) Result {
	return Result{Name: name, OK: false, Detail: detail, Hint: hint}
}

func checkFile(name, path string) Result {
	if _, err := os.Stat(path); err != nil {
		return fail(name, err.Error(), "check the path exists and is readable by the coen user")
	}
	return ok(name, path)
}

func checkBind(name, addr, adminSocket string) Result {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		_ = ln.Close()
		return ok(name, addr)
	}
	// Could not bind. If a coen daemon is answering on the admin socket, the
	// port is almost certainly held by that running daemon (the normal case
	// when debugging a live host), not a genuine conflict.
	if adminSocket != "" {
		if _, sErr := admin.Status(adminSocket); sErr == nil {
			return ok(name, addr+" (in use by the running coen daemon)")
		}
	}
	return fail(name, err.Error(), "another process may hold the port, or you lack permission to bind it (:443 needs CAP_NET_BIND_SERVICE)")
}

// CheckAgent runs preflight checks for the agent role.
func CheckAgent(cfg *config.AgentConfig) []Result {
	var out []Result
	out = append(out, checkFile("pki: ca", cfg.Edge.CA))
	out = append(out, checkFile("pki: client cert", cfg.Edge.Cert))
	out = append(out, checkFile("pki: client key", cfg.Edge.Key))

	if pin := cfg.Edge.EdgeFingerprint; pin != "" {
		if err := pki.ValidateFingerprint(pin); err != nil {
			out = append(out, fail("config: edge_fingerprint", err.Error(), "edge_fingerprint must be a SHA256:... value, or empty to disable pinning"))
		} else {
			out = append(out, ok("config: edge_fingerprint", "well-formed"))
		}
	}

	caPEM, err := os.ReadFile(cfg.Edge.CA)
	if err != nil {
		return append(out, fail("pki: ca parse", err.Error(), "run `coen cert init` to create the CA"))
	}
	pool, err := pki.CertPoolFromPEM(caPEM)
	if err != nil {
		return append(out, fail("pki: ca parse", err.Error(), "ca.crt is not a valid PEM certificate"))
	}
	clientCert, err := tls.LoadX509KeyPair(cfg.Edge.Cert, cfg.Edge.Key)
	if err != nil {
		out = append(out, fail("pki: client keypair", err.Error(), "cert/key mismatch or unreadable; re-issue with `coen cert agent`"))
	} else {
		out = append(out, ok("pki: client keypair", "loaded"))
	}

	host, port, err := net.SplitHostPort(cfg.Edge.Address)
	if err != nil {
		return append(out, fail("dns: edge address", err.Error(), "edge.address must be host:port"))
	}
	if _, err := net.LookupHost(host); err != nil {
		out = append(out, fail("dns: resolve edge", err.Error(), "check the hostname or use an IP"))
	} else {
		out = append(out, ok("dns: resolve edge", host))
	}

	addr := net.JoinHostPort(host, port)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return append(out, fail("net: tcp reach", err.Error(), fmt.Sprintf("open port %s on the edge / firewall", port)))
	}
	_ = c.Close()
	out = append(out, ok("net: tcp reach", addr))

	clientTLS := tunnel.ClientTLSConfig(pool, clientCert, host)
	tconn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, clientTLS)
	if err != nil {
		out = append(out, fail("mtls: handshake", err.Error(), "verify the CA matches on both hosts and the edge cert covers "+host))
	} else {
		leaf := tconn.ConnectionState().PeerCertificates[0]
		edgeFP := pki.Fingerprint(leaf)
		out = append(out, ok("mtls: handshake", "transport TLS ok, edge fingerprint "+edgeFP+" (route authorization is enforced by the edge, not verified here)"))
		if pin := cfg.Edge.EdgeFingerprint; pin != "" && pin != edgeFP {
			out = append(out, fail("mtls: pin", fmt.Sprintf("got %s want %s", edgeFP, pin), "update edge_fingerprint or the edge certificate"))
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			out = append(out, fail("time: cert validity", fmt.Sprintf("now=%s window=[%s,%s]", now.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339)), "check the system clock (NTP) or re-issue the certificate"))
		} else {
			out = append(out, ok("time: cert validity", "within the edge certificate window"))
		}
		_ = tconn.Close()
	}

	for _, r := range cfg.Routes {
		sc, err := net.DialTimeout("tcp", r.Service, 3*time.Second)
		if err != nil {
			out = append(out, fail("service: reach "+r.Host, err.Error(), "start the local service or fix the route's service address"))
			continue
		}
		_ = sc.Close()
		out = append(out, ok("service: reach "+r.Host, r.Service))
	}
	return out
}

// CheckEdge runs preflight checks for the edge role.
func CheckEdge(cfg *config.EdgeConfig) []Result {
	var out []Result
	out = append(out, checkFile("pki: ca", cfg.Tunnel.CA))
	out = append(out, checkFile("pki: edge cert", cfg.Tunnel.Cert))
	out = append(out, checkFile("pki: edge key", cfg.Tunnel.Key))

	if caPEM, err := os.ReadFile(cfg.Tunnel.CA); err != nil {
		out = append(out, fail("pki: ca parse", err.Error(), "run `coen cert init`"))
	} else if _, err := pki.CertPoolFromPEM(caPEM); err != nil {
		out = append(out, fail("pki: ca parse", err.Error(), "ca.crt is not a valid PEM certificate"))
	} else {
		out = append(out, ok("pki: ca parse", "valid"))
	}

	if _, err := tls.LoadX509KeyPair(cfg.Tunnel.Cert, cfg.Tunnel.Key); err != nil {
		out = append(out, fail("pki: edge keypair", err.Error(), "re-issue with `coen cert edge`"))
	} else {
		out = append(out, ok("pki: edge keypair", "loaded"))
	}

	if cfg.Ingress.Mode == "standalone" {
		if _, err := tls.LoadX509KeyPair(cfg.Ingress.TLS.Cert, cfg.Ingress.TLS.Key); err != nil {
			out = append(out, fail("pki: public cert", err.Error(), "provide a valid public PEM cert/key"))
		} else {
			out = append(out, ok("pki: public cert", "loaded"))
		}
	}

	for _, r := range cfg.Routes {
		if err := pki.ValidateFingerprint(r.AgentFingerprint); err != nil {
			out = append(out, fail("config: fingerprint "+r.Host, err.Error(), "agent_fingerprint must be the SHA256:... value printed by `coen cert agent`"))
		} else {
			out = append(out, ok("config: fingerprint "+r.Host, "well-formed"))
		}
	}

	out = append(out, checkBind("bind: tunnel", cfg.Tunnel.Listen, cfg.Admin.Socket))
	out = append(out, checkBind("bind: ingress", cfg.Ingress.Listen, cfg.Admin.Socket))
	return out
}
