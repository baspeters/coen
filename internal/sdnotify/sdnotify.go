// Package sdnotify sends service status to systemd (sd_notify), for units
// with Type=notify. Without $NOTIFY_SOCKET (not started that way) it does
// nothing.
package sdnotify

import (
	"net"
	"os"
	"strings"
)

// Available reports whether systemd listens for notifications: the unit is
// Type=notify (or similar), so it can be told the service is ready, and that
// another process has taken over as its main process.
func Available() bool { return os.Getenv("NOTIFY_SOCKET") != "" }

// Notify sends state, one or more "KEY=value" lines such as "READY=1" or
// "MAINPID=1234", and reports whether there was a socket to send it to.
func Notify(state string) (bool, error) {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return false, nil
	}
	if strings.HasPrefix(path, "@") {
		path = "\x00" + path[1:] // an abstract socket
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return true, err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return true, err
}
