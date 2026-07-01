package proxy

import (
	"errors"
	"io"
	"net"
)

// Pipe copies bidirectionally between a and b until one direction ends,
// then closes both to unblock the other. Returns bytes copied a→b and b→a.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64, err error) {
	errc := make(chan error, 2)
	go func() {
		n, e := io.Copy(b, a)
		aToB = n
		errc <- e
	}()
	go func() {
		n, e := io.Copy(a, b)
		bToA = n
		errc <- e
	}()
	e1 := <-errc
	_ = a.Close()
	_ = b.Close()
	e2 := <-errc
	for _, e := range []error{e1, e2} {
		if e != nil && !errors.Is(e, io.EOF) && !errors.Is(e, net.ErrClosed) {
			err = e
			break
		}
	}
	return aToB, bToA, err
}
