package proxy

import (
	"errors"
	"io"
	"net"
)

// Pipe copies bidirectionally between a and b until one direction ends,
// then closes both to unblock the other. Returns bytes copied a→b and b→a.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64, err error) {
	return PipeProgress(a, b, nil, nil)
}

// PipeProgress is Pipe that also reports bytes as they are written, so a
// long-lived stream (a WebSocket, a large download) is visible while it runs.
// onAToB and onBToA, when non-nil, are called after every write with the bytes
// just written in that direction; the two run on different goroutines.
func PipeProgress(a, b io.ReadWriteCloser, onAToB, onBToA func(int64)) (aToB, bToA int64, err error) {
	errc := make(chan error, 2)
	var toB, toA io.Writer = b, a
	if onAToB != nil {
		toB = progressWriter{b, onAToB}
	}
	if onBToA != nil {
		toA = progressWriter{a, onBToA}
	}
	// aToB/bToA are written by the goroutines below and read only after both
	// have sent to errc (drained via e1,e2), so the channel receives establish
	// happens-before — no data race on the named returns.
	go func() {
		n, e := io.Copy(toB, a)
		aToB = n
		errc <- e
	}()
	go func() {
		n, e := io.Copy(toA, b)
		bToA = n
		errc <- e
	}()
	e1 := <-errc
	_ = a.Close()
	_ = b.Close()
	e2 := <-errc
	for _, e := range []error{e1, e2} {
		if e != nil && !errors.Is(e, io.EOF) && !errors.Is(e, net.ErrClosed) && !errors.Is(e, io.ErrClosedPipe) {
			err = e
			break
		}
	}
	return aToB, bToA, err
}

// progressWriter reports each successful write's byte count.
type progressWriter struct {
	w      io.Writer
	report func(int64)
}

func (p progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 {
		p.report(int64(n))
	}
	return n, err
}
