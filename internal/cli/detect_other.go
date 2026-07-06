//go:build !linux && !darwin

package cli

// enumerateDaemons cannot inspect the process table on platforms other than
// Linux and macOS, so role auto-detection is unavailable there and callers fall
// back to requiring --role.
func enumerateDaemons() ([]daemon, error) { return nil, nil }
