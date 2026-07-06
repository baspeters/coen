package tunnel

import (
	"crypto/tls"
	"crypto/x509"
)

func ServerTLSConfig(caPool *x509.CertPool, cert tls.Certificate) *tls.Config {
	if caPool == nil {
		// Fail closed: an empty pool trusts no client, rather than a nil ClientCAs
		// which would be a programmer error in this mTLS-only design.
		caPool = x509.NewCertPool()
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
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
	}
}
