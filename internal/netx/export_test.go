package netx

import (
	"crypto/x509"
	"testing"
)

// SetProxyRootCAs makes Dial trust pool for https:// proxies until the test
// ends.
func SetProxyRootCAs(t testing.TB, pool *x509.CertPool) {
	old := proxyRootCAs
	proxyRootCAs = pool
	t.Cleanup(func() { proxyRootCAs = old })
}
