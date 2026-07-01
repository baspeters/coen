package tunnel

import (
	"crypto/tls"
	"crypto/x509"
)

func ServerTLSConfig(caPool *x509.CertPool, cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

func ClientTLSConfig(caPool *x509.CertPool, cert tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}
