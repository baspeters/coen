package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// daemon describes a running coen edge/agent process discovered on the host.
type daemon struct {
	pid    int
	role   string // "edge" or "agent"
	config string // --config path from the process's argv, or the role default
}

// errNoDaemon is returned by detectRole when no coen daemon is running.
var errNoDaemon = errors.New("no running coen daemon found")

// enumerate lists the running coen daemons. It is a package var over the
// OS-specific implementation so tests can inject a fake process list.
var enumerate = enumerateDaemons

// detectRole determines the role from the single running coen daemon by reading
// the OS process table (ground truth, immune to config files being edited or
// moved). It returns errNoDaemon if none is running, or an error if both an
// edge and an agent are running (genuinely ambiguous -> the caller asks for
// --role).
func detectRole() (role, config string, err error) {
	ds, err := enumerate()
	if err != nil {
		return "", "", fmt.Errorf("inspect running processes: %w", err)
	}
	byRole := make(map[string]daemon, 2)
	for _, d := range ds {
		byRole[d.role] = d
	}
	switch len(byRole) {
	case 0:
		return "", "", errNoDaemon
	case 1:
		for _, d := range byRole {
			return d.role, d.config, nil
		}
	}
	return "", "", errors.New("both edge and agent daemons are running; pass --role")
}

// parseDaemon inspects one process's argv (argv[0] being the executable path)
// and returns a daemon if it is a coen edge/agent daemon. Matching on the
// executable basename plus the subcommand means a process that merely mentions
// "coen edge" in its arguments (a grep, an editor, `coen doctor` itself) does
// not match.
func parseDaemon(pid int, argv []string) (daemon, bool) {
	if len(argv) < 2 || filepath.Base(argv[0]) != "coen" {
		return daemon{}, false
	}
	role := argv[1]
	if role != "edge" && role != "agent" {
		return daemon{}, false
	}
	return daemon{pid: pid, role: role, config: configFromArgs(argv[2:], role)}, true
}

// configFromArgs extracts the --config path the daemon was actually started
// with (so status/doctor honor a non-default config location), falling back to
// the documented default for the role.
func configFromArgs(args []string, role string) string {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(args[i], "--config="):
			return strings.TrimPrefix(args[i], "--config=")
		}
	}
	return filepath.Join("/etc/coen", role+".yaml")
}
