package edge

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baspeters/coen/internal/config"
)

// takeAgent only takes TLS connections from the edge's own listener.
func TestTakeAgentOnlyFromTheSharedListener(t *testing.T) {
	e := &Edge{cfg: &config.EdgeConfig{Tunnel: config.TunnelServerConfig{ShareIngress: true}}}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if e.takeAgent(a, time.Now().Add(time.Second)) {
		t.Fatal("a plain connection is not an agent's")
	}
	if e.takeAgent(tls.Server(a, &tls.Config{}), time.Now().Add(time.Second)) {
		t.Fatal("a TLS connection not from the ingress listener is not an agent's")
	}
	e.cfg.Tunnel.ShareIngress = false
	if e.takeAgent(a, time.Now()) {
		t.Fatal("without share_ingress nothing is taken")
	}
}

// Run and ServeWithHTTP3 close what they opened when a later listener fails.
func TestRunClosesListenersOnHTTP3Failure(t *testing.T) {
	e, tunLn, ingressLn, _ := newTestEdge(t)
	_ = tunLn.Close()
	_ = ingressLn.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	e.cfg.Tunnel.Listen = "127.0.0.1:0"
	e.cfg.Ingress.Listen = "127.0.0.1:0"
	e.cfg.Ingress.HTTP3 = config.HTTP3Config{Enabled: true, Listen: udp.LocalAddr().String()} // taken
	if err := e.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "http3 listen") {
		t.Fatalf("got %v", err)
	}

	// Standalone HTTP/3 whose public certificate cannot be loaded.
	e2, tunLn2, ingressLn2, _ := newTestEdge(t)
	e2.cfg.Ingress.Mode = "standalone"
	e2.cfg.Ingress.TLS = config.TLSFiles{Cert: "/nonexistent.crt", Key: "/nonexistent.key"}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.ServeWithHTTP3(context.Background(), tunLn2, ingressLn2, pc); err == nil || !strings.Contains(err.Error(), "public cert") {
		t.Fatalf("got %v", err)
	}
	if _, err := tunLn2.Accept(); err == nil {
		t.Fatal("the tunnel listener must be closed")
	}
}
