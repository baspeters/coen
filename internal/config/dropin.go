package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/baspeters/coen/internal/route"
	"gopkg.in/yaml.v3"
)

// dropInDir returns the "<name>.d" directory that sits next to a config file:
// /etc/coen/edge.yaml -> /etc/coen/edge.d.
func dropInDir(path string) string {
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return filepath.Join(filepath.Dir(path), name+".d")
}

// sourced pairs a host pattern with the file it came from, for error messages.
type sourced struct {
	host   string
	origin string
}

// readEdgeDropIns loads routes from every *.yaml in the drop-in dir (sorted),
// strict-decoding each as a routes-only fragment. A missing dir is not an error.
func readEdgeDropIns(path string) ([]EdgeRoute, []string, error) {
	files, err := dropInFiles(path)
	if err != nil {
		return nil, nil, err
	}
	var routes []EdgeRoute
	var origins []string
	for _, f := range files {
		var frag struct {
			Routes []EdgeRoute `yaml:"routes"`
		}
		if err := strictDecodeFile(f, &frag); err != nil {
			return nil, nil, err
		}
		for _, r := range frag.Routes {
			routes = append(routes, r)
			origins = append(origins, dropInLabel(path, f))
		}
	}
	return routes, origins, nil
}

// readAgentDropIns is the agent-side counterpart of readEdgeDropIns.
func readAgentDropIns(path string) ([]AgentRoute, []string, error) {
	files, err := dropInFiles(path)
	if err != nil {
		return nil, nil, err
	}
	var routes []AgentRoute
	var origins []string
	for _, f := range files {
		var frag struct {
			Routes []AgentRoute `yaml:"routes"`
		}
		if err := strictDecodeFile(f, &frag); err != nil {
			return nil, nil, err
		}
		for _, r := range frag.Routes {
			routes = append(routes, r)
			origins = append(origins, dropInLabel(path, f))
		}
	}
	return routes, origins, nil
}

func dropInFiles(path string) ([]string, error) {
	dir := dropInDir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read drop-in dir %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			names = append(names, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(names)
	return names, nil
}

func dropInLabel(base, full string) string {
	return filepath.Join(filepath.Base(dropInDir(base)), filepath.Base(full))
}

func strictDecodeFile(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// checkDuplicateHosts fails if any normalized host pattern appears twice,
// naming both source files. Patterns are assumed already validated by Validate.
func checkDuplicateHosts(hosts []sourced) error {
	seen := make(map[string]string)
	for _, h := range hosts {
		key := route.Normalize(h.host)
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("duplicate host %q in %s (already defined in %s)", h.host, h.origin, prev)
		}
		seen[key] = h.origin
	}
	return nil
}
