package edge

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 defines Sec-WebSocket-Accept with SHA-1
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/baspeters/coen/internal/obs"
)

// WebSockets over HTTP/3 (RFC 9220). The HTTP/3 server always offers
// extended CONNECT, so a browser may open a WebSocket over HTTP/3. The edge
// bridges it to the HTTP/1.1 upgrade the agent and backend already speak:
// an extended CONNECT with :protocol websocket becomes a GET with
// Upgrade: websocket on the tunnel stream, the backend's 101 becomes a 200
// to the client, and from then on WebSocket frames pass through unchanged in
// both directions (they are the same bytes in both protocols).

// closeGrace is how long a WebSocket's backend side may take to finish
// after the client has ended its side (the closing handshake).
var closeGrace = 5 * time.Second

// isWebSocketConnect reports an extended CONNECT for a WebSocket.
func isWebSocketConnect(r *http.Request) bool {
	return r.Method == http.MethodConnect && strings.EqualFold(r.Proto, "websocket")
}

// webSocketHead renders the HTTP/1.1 upgrade request for an extended CONNECT
// r, with key as its Sec-WebSocket-Key.
func webSocketHead(r *http.Request, key string) ([]byte, error) {
	up := r.Clone(r.Context())
	up.Method = http.MethodGet
	up.Header.Del("Sec-Websocket-Key")
	lines, err := http1Lines(up)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBuffer(lines)
	// "close" too: should the service turn the upgrade down, it ends the
	// connection after its answer, whatever that answer's framing.
	b.WriteString("Upgrade: websocket\r\nConnection: Upgrade, close\r\nSec-WebSocket-Key: " + key + "\r\n")
	if up.Header.Get("Sec-Websocket-Version") == "" {
		b.WriteString("Sec-WebSocket-Version: 13\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// newWebSocketKey returns a fresh Sec-WebSocket-Key.
func newWebSocketKey() string {
	var k [16]byte
	_, _ = rand.Read(k[:])
	return base64.StdEncoding.EncodeToString(k[:])
}

// webSocketAccept is the Sec-WebSocket-Accept a server answers key with.
func webSocketAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- RFC 6455
	return base64.StdEncoding.EncodeToString(h[:])
}

// serveHTTP3WebSocket bridges an extended CONNECT WebSocket request whose
// stream is already open (head sent, accounting started) to the backend.
func (e *Edge) serveHTTP3WebSocket(w http.ResponseWriter, r *http.Request, tunnelSide *countingConn, headLen int64, key string, log *slog.Logger, fail func(int, string, string), failure func(obs.Reason)) {
	limited := newHeadLimit(tunnelSide)
	br := bufio.NewReaderSize(limited, 16<<10)
	resp, err := readUpgradeResponse(br, limited)
	if err == nil {
		limited.done()
	}
	if err != nil {
		if r.Context().Err() != nil {
			panic(http.ErrAbortHandler) // the client gave up
		}
		reason := obs.ReasonBadResponse
		if isTunnelGone(err) {
			reason = obs.ReasonStreamError
		}
		failure(reason)
		log.Warn("stream.bad_response", "error", err.Error())
		fail(502, "Bad Gateway", "Invalid response from the service")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols:
	case resp.StatusCode < 300:
		// A 1xx or 2xx would tell an HTTP/3 client the tunnel is open: the
		// service ignored the upgrade, which is an error here.
		failure(obs.ReasonBadResponse)
		log.Warn("stream.bad_upgrade", "status", resp.StatusCode)
		fail(502, "Bad Gateway", "The service did not accept the WebSocket")
		return
	default:
		// The service turned the upgrade down (403, 404, ...): pass its answer on.
		copyResponseHeader(w.Header(), resp.Header)
		if _, ok := resp.Header["Content-Type"]; !ok {
			w.Header()["Content-Type"] = nil // no guessed type (see serveHTTP3)
		}
		w.WriteHeader(resp.StatusCode)
		if err := copyResponse(w, resp.Body, true, e.cfg.Ingress.IdleTimeout.Duration()); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	if resp.Header.Get("Sec-Websocket-Accept") != webSocketAccept(key) {
		failure(obs.ReasonBadResponse)
		log.Warn("stream.bad_upgrade", "error", "wrong Sec-WebSocket-Accept")
		fail(502, "Bad Gateway", "Invalid response from the service")
		return
	}
	// The service's headers go on (its chosen subprotocol and extensions
	// among them), less what belongs to the HTTP/1.1 handshake itself.
	copyResponseHeader(w.Header(), resp.Header)
	w.Header().Del("Sec-Websocket-Accept")
	w.WriteHeader(http.StatusOK) // RFC 8441: the upgrade's 101 is a 2xx here
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	// Frames both ways. When the backend side ends, both are closed. When
	// the client ends its side cleanly (it has sent its Close frame), the
	// backend gets closeGrace to send its own Close frame and finish, as the
	// closing handshake needs.
	up := make(chan error, 1)
	down := make(chan struct{})
	go func() {
		_, err := io.Copy(tunnelSide, r.Body)
		up <- err
	}()
	go func() {
		defer close(down)
		_ = copyResponse(w, br, true, e.cfg.Ingress.IdleTimeout.Duration()) // bytes after the 101 are in br
	}()
	upDone := false
	select {
	case <-down:
	case err := <-up:
		upDone = true
		if err == nil { // a clean end of the client's side
			select {
			case <-down:
			case <-time.After(closeGrace):
			}
		}
	}
	// Closing both ends any copy still running, so both are waited for: the
	// body is not read once the handler returns. A write to a client that has
	// stopped reading is ended by an expired deadline.
	abort(tunnelSide)
	_ = r.Body.Close()
	_ = rc.SetWriteDeadline(time.Now())
	<-down
	if !upDone {
		<-up
	}
	log.Debug("stream.closed", "bytes_in", headLen+tunnelSide.inTotal, "bytes_out", tunnelSide.outTotal)
}
