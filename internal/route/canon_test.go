package route

import "testing"

// A pattern carrying a trailing dot or a port must still match the normalized
// host, rather than loading cleanly and then black-holing all its traffic.
func TestBuildCanonicalizesTrailingDotAndPort(t *testing.T) {
	m := Build([]Entry[string]{
		{Pattern: "app.example.com.", Value: "exact"},
		{Pattern: "*.api.example.com.", Value: "wild"},
		{Pattern: "svc.example.com:443", Value: "port"},
	})
	cases := map[string]string{
		"app.example.com":   "exact",
		"x.api.example.com": "wild",
		"svc.example.com":   "port",
	}
	for host, want := range cases {
		if v, ok := m.Match(host); !ok || v != want {
			t.Fatalf("Match(%q) = %q,%v; want %q", host, v, ok, want)
		}
	}
}
