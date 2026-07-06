//go:build unix

package obs

import (
	"os"
	"syscall"
)

func fileMatchesDevIno(f *os.File, dev, ino uint64) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(st.Dev) == dev && uint64(st.Ino) == ino
}
