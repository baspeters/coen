package config

import (
	"path/filepath"
	"testing"
)

// TestExampleConfigsAreValid loads every example config so the examples never
// drift from the schema. Top-level edge*.yaml / agent*.yaml files are loaded;
// drop-in files under */edge.d/ are merged in by LoadEdge itself.
func TestExampleConfigsAreValid(t *testing.T) {
	root := "../../examples"
	edges, _ := filepath.Glob(filepath.Join(root, "*", "edge*.yaml"))
	agents, _ := filepath.Glob(filepath.Join(root, "*", "agent*.yaml"))
	if len(edges) == 0 || len(agents) == 0 {
		t.Fatalf("found no example configs under %s (edges=%d agents=%d)", root, len(edges), len(agents))
	}
	for _, f := range edges {
		if _, err := LoadEdge(f); err != nil {
			t.Errorf("LoadEdge(%s): %v", f, err)
		}
	}
	for _, f := range agents {
		if _, err := LoadAgent(f); err != nil {
			t.Errorf("LoadAgent(%s): %v", f, err)
		}
	}
}
