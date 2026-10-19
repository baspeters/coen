package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/baspeters/coen/internal/config"
)

// probeTimeout bounds one probe request.
const probeTimeout = 3 * time.Second

// Holder describes the coen daemon answering on a metrics address.
type Holder struct {
	Role     string
	Draining bool
}

// ServesRole reports whether addr (a metrics.listen value) answers GET /metrics
// with the metrics of a coen daemon of the given role. coen doctor uses it to
// tell its own running daemon's endpoint from a foreign process on the port.
func ServesRole(addr, role string) bool {
	h, ok := Probe(context.Background(), addr)
	return ok && h.Role == role
}

// Probe asks addr (a metrics.listen value) for its metrics and, if a coen
// daemon answers, returns its role and whether it is draining. A wildcard
// address is probed on both loopbacks, since such a socket may accept only one
// address family.
//
// ctx cancels the probe (for example on shutdown); each request is also
// bounded by probeTimeout.
func Probe(ctx context.Context, addr string) (Holder, bool) {
	host, port, err := config.SplitListen(addr)
	if err != nil {
		return Holder{}, false
	}
	hosts := config.LoopbackHosts(host)
	type answer struct {
		h  Holder
		ok bool
	}
	// Probe all candidates at once, so a holder that accepts but never answers
	// costs one timeout rather than one per address.
	found := make(chan answer, len(hosts))
	for _, h := range hosts {
		go func(hostport string) {
			hl, ok := probeOne(ctx, hostport)
			found <- answer{hl, ok}
		}(net.JoinHostPort(h, strconv.Itoa(port)))
	}
	for range hosts {
		if a := <-found; a.ok {
			return a.h, true
		}
	}
	return Holder{}, false
}

func probeOne(ctx context.Context, hostport string) (Holder, bool) {
	// Proxy: nil, so HTTP_PROXY in the operator's shell cannot reroute a probe
	// meant for a local or private address. No keep-alive: one request per probe.
	cl := &http.Client{Timeout: probeTimeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+hostport+"/metrics", nil)
	if err != nil {
		return Holder{}, false
	}
	resp, err := cl.Do(req)
	if err != nil {
		return Holder{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return Holder{}, false
	}
	role, ok := BuildInfoRole(string(body))
	if !ok {
		return Holder{}, false
	}
	return Holder{Role: role, Draining: Draining(string(body))}, true
}
