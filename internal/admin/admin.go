package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/baspeters/coen/internal/obs"
)

// Server answers status/control requests on a local Unix socket.
type Server struct {
	Snapshot func() obs.Snapshot
	SetLevel func(slog.Level) error
}

func (s *Server) Serve(ctx context.Context, socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("admin listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "status":
		b, _ := json.Marshal(s.Snapshot())
		_, _ = conn.Write(append(b, '\n'))
	case "level":
		if len(fields) != 2 {
			fmt.Fprintln(conn, "error: usage: level <name>")
			return
		}
		lvl, err := obs.ParseLevel(fields[1])
		if err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		if err := s.SetLevel(lvl); err != nil {
			fmt.Fprintf(conn, "error: %v\n", err)
			return
		}
		fmt.Fprintln(conn, "ok")
	default:
		fmt.Fprintln(conn, "error: unknown command")
	}
}

// Status connects to the admin socket and returns the daemon snapshot.
func Status(socketPath string) (obs.Snapshot, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return obs.Snapshot{}, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("status\n")); err != nil {
		return obs.Snapshot{}, err
	}
	var snap obs.Snapshot
	if err := json.NewDecoder(conn).Decode(&snap); err != nil {
		return obs.Snapshot{}, err
	}
	return snap, nil
}

// SetLevel connects to the admin socket and changes the runtime log level.
func SetLevel(socketPath, level string) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(conn, "level %s\n", level)
	resp, _ := bufio.NewReader(conn).ReadString('\n')
	if resp = strings.TrimSpace(resp); resp != "ok" {
		return fmt.Errorf("%s", resp)
	}
	return nil
}
