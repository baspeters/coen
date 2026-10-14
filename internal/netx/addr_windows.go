// Package netx classifies network errors the same way on every platform.
package netx

import (
	"errors"
	"syscall"
)

// Winsock's codes, which Windows reports instead of the POSIX errno values.
const (
	wsaeaddrinuse    = syscall.Errno(10048) // WSAEADDRINUSE
	wsaeaddrnotavail = syscall.Errno(10049) // WSAEADDRNOTAVAIL
)

// IsAddrInUse reports whether a listen error means the port is taken.
func IsAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, wsaeaddrinuse)
}

// IsAddrNotAvail reports whether a listen error means the address is not one
// of this host's.
func IsAddrNotAvail(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, wsaeaddrnotavail)
}
