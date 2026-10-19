//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package admin

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockSocketPath takes an exclusive lock on a sidecar file next to the socket,
// so one daemon's replace-and-listen and another's check-and-remove of the same
// socket path never interleave. The lock is held only for those few calls, so
// it is waited for at most wait. state says whether it was taken, could not be
// used at all (no lock file: proceed unlocked, as before locking existed), or
// is held by another process past wait (a daemon is busy with the path).
//
// The <socket>.lock file is left in place on exit: removing a lock file safely
// is not possible while another process may be about to lock it, and an empty
// file next to the socket is harmless (it lives in the same runtime directory,
// /run/coen under the systemd unit, which is cleared on reboot).
func lockSocketPath(socketPath string, wait time.Duration) (unlock func(), state lockState) {
	f, err := os.OpenFile(socketPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, lockUnavailable
	}
	// Never block indefinitely: a stuck holder must not stall startup or, on
	// the shutdown path, keep the daemon from exiting.
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return func() {}, lockUnavailable
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return func() {}, lockContended
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, lockHeld
}
