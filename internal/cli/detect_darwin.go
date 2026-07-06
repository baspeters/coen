//go:build darwin

package cli

import (
	"os/exec"
	"strconv"
	"strings"
)

// enumerateDaemons finds running coen daemons on macOS via `ps` (which reads the
// live kernel process table), the same approach gopsutil uses on darwin, but
// without its dependency. Args with embedded spaces are not reconstructed, but
// the role only needs argv[0]/argv[1] and a --config path, none of which
// contain spaces for a coen daemon.
func enumerateDaemons() ([]daemon, error) {
	out, err := exec.Command("ps", "-axo", "pid=,args=").Output()
	if err != nil {
		return nil, err
	}
	var ds []daemon
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if d, ok := parseDaemon(pid, fields[1:]); ok {
			ds = append(ds, d)
		}
	}
	return ds, nil
}
