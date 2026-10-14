//go:build !windows

// Package netx classifies network errors the same way on every platform.
package netx

import (
	"errors"
	"syscall"
)

// IsAddrInUse reports whether a listen error means the port is taken.
func IsAddrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

// IsAddrNotAvail reports whether a listen error means the address is not one
// of this host's.
func IsAddrNotAvail(err error) bool { return errors.Is(err, syscall.EADDRNOTAVAIL) }
