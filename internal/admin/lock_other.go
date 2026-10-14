//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package admin

import "time"

// lockSocketPath is a no-op where flock is unavailable (Windows, Solaris,
// illumos, AIX, Plan 9, and others).
func lockSocketPath(string, time.Duration) (unlock func(), state lockState) {
	return func() {}, lockUnavailable
}
