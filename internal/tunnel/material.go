package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/baspeters/coen/internal/pki"
)

// LoadMaterial reads the CA bundle and the certificate/key pair used for the
// mTLS tunnel, returning a trust pool and the keypair. certLabel names the
// certificate in the load error (for example "edge cert" or "client cert") so
// both roles can share this one implementation of trust-material loading.
func LoadMaterial(caPath, certPath, keyPath, certLabel string) (*x509.CertPool, tls.Certificate, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("read ca: %w", err)
	}
	pool, err := pki.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("load %s: %w", certLabel, err)
	}
	return pool, cert, nil
}
