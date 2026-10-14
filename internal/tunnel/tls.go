package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
)

// ALPNv2 is the TLS application protocol both ends advertise for the version 2
// tunnel features: the drain handshake on shutdown (see RequestDrain) and the
// per-stream accept byte (see Accept and AwaitAccept). Negotiating it in the
// handshake tells each side, per session and before any traffic, that the
// other supports them. An older edge or agent advertises nothing; Go's TLS
// then negotiates no protocol and both sides keep the version 1 behaviour.
// Every future protocol list must keep this value.
const ALPNv2 = "coen/2"

func ServerTLSConfig(caPool *x509.CertPool, cert tls.Certificate) *tls.Config {
	if caPool == nil {
		// Fail closed: an empty pool trusts no client, rather than a nil ClientCAs
		// which would be a programmer error in this mTLS-only design.
		caPool = x509.NewCertPool()
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNv2},
	}
	// Offer ALPNv2 only to a client that asks for it. Go's TLS server rejects
	// a client whose ALPN list shares nothing with NextProtos; answering with
	// no NextProtos instead lets any other client (a future version, or one
	// that asks for something else) connect with version 1 behaviour.
	plain := base.Clone()
	plain.NextProtos = nil
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Contains(hello.SupportedProtos, ALPNv2) {
			return nil, nil // use base
		}
		return plain, nil
	}
	return base
}

func ClientTLSConfig(caPool *x509.CertPool, cert tls.Certificate, serverName string) *tls.Config {
	if caPool == nil {
		// Fail closed: nil RootCAs would silently fall back to the system trust
		// store, broadening trust for a tunnel that must only trust the coen CA.
		caPool = x509.NewCertPool()
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNv2},
	}
}
