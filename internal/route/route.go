// Package route resolves an HTTP request host to a value using
// exact > wildcard (*.suffix) > default (*) precedence. It is shared by
// the edge (host -> owning agent) and the agent (host -> local backend).
package route

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Normalize lowercases a host and strips any :port and trailing dot.
func Normalize(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// ValidatePattern rejects malformed host patterns. Valid forms: "*" (default),
// "*.suffix" (wildcard), or a literal host. "*" may only appear as the whole
// pattern or as a leading "*.".
func ValidatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("empty host pattern")
	}
	if p == "*" {
		return nil
	}
	if strings.HasPrefix(p, "*.") {
		rest := p[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return fmt.Errorf("invalid wildcard pattern %q", p)
		}
		return nil
	}
	if strings.Contains(p, "*") {
		return fmt.Errorf("invalid host pattern %q (\"*\" only allowed as \"*\" or leading \"*.\")", p)
	}
	return nil
}

// Entry pairs a host pattern with the value it resolves to.
type Entry[V any] struct {
	Pattern string
	Value   V
}

type wildcard[V any] struct {
	suffix string // the part after "*."
	val    V
}

// Matcher resolves hosts to values. Build it once; Match is safe for concurrent use.
type Matcher[V any] struct {
	exact    map[string]V
	wildcard []wildcard[V] // sorted by suffix length, longest first
	def      V
	hasDef   bool
}

// Build constructs a Matcher. Patterns must already be validated and unique
// (config validation guarantees this).
func Build[V any](entries []Entry[V]) *Matcher[V] {
	m := &Matcher[V]{exact: make(map[string]V)}
	for _, e := range entries {
		switch {
		case e.Pattern == "*":
			m.def, m.hasDef = e.Value, true
		case strings.HasPrefix(e.Pattern, "*."):
			m.wildcard = append(m.wildcard, wildcard[V]{suffix: strings.ToLower(e.Pattern[2:]), val: e.Value})
		default:
			m.exact[strings.ToLower(e.Pattern)] = e.Value
		}
	}
	sort.SliceStable(m.wildcard, func(i, j int) bool {
		return len(m.wildcard[i].suffix) > len(m.wildcard[j].suffix)
	})
	return m
}

// Match returns the value whose pattern best matches host.
func (m *Matcher[V]) Match(host string) (V, bool) {
	host = Normalize(host)
	if v, ok := m.exact[host]; ok {
		return v, true
	}
	for _, w := range m.wildcard {
		if strings.HasSuffix(host, "."+w.suffix) {
			return w.val, true
		}
	}
	if m.hasDef {
		return m.def, true
	}
	var zero V
	return zero, false
}
