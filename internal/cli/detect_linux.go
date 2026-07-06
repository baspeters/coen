//go:build linux

package cli

import (
	"os"
	"strconv"
	"strings"
)

// enumerateDaemons finds running coen daemons via /proc, reading each process's
// argv and resolving its real executable (so argv[0] cannot be spoofed).
func enumerateDaemons() ([]daemon, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var ds []daemon
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a /proc/<pid> directory
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		argv := splitNUL(raw)
		if len(argv) == 0 {
			continue
		}
		// Prefer the resolved executable path over argv[0], which a process can
		// set to anything.
		if exe, err := os.Readlink("/proc/" + e.Name() + "/exe"); err == nil {
			argv[0] = exe
		}
		if d, ok := parseDaemon(pid, argv); ok {
			ds = append(ds, d)
		}
	}
	return ds, nil
}

func splitNUL(b []byte) []string {
	var out []string
	for _, p := range strings.Split(string(b), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
