//go:build !unix

package obs

import "os"

// fileMatchesDevIno cannot inspect journald streams on non-unix platforms, where
// the coen daemons do not run; format resolution falls back to text.
func fileMatchesDevIno(*os.File, uint64, uint64) bool { return false }
