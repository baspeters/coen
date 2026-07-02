package route

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"App.Example.com":     "app.example.com",
		"app.example.com:443": "app.example.com",
		" app.example.com. ":  "app.example.com",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	for _, ok := range []string{"*", "*.example.com", "app.example.com"} {
		if err := ValidatePattern(ok); err != nil {
			t.Errorf("ValidatePattern(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*.", "a*.example.com", "app.*.com"} {
		if err := ValidatePattern(bad); err == nil {
			t.Errorf("ValidatePattern(%q) expected error", bad)
		}
	}
}

func TestMatchPrecedence(t *testing.T) {
	m := Build([]Entry[string]{
		{Pattern: "*", Value: "default"},
		{Pattern: "*.example.com", Value: "wild"},
		{Pattern: "*.sub.example.com", Value: "wild-long"},
		{Pattern: "app.example.com", Value: "exact"},
	})
	cases := map[string]struct {
		val string
		ok  bool
	}{
		"app.example.com":     {"exact", true},    // exact beats wildcard
		"foo.example.com":     {"wild", true},      // wildcard
		"foo.sub.example.com": {"wild-long", true}, // longest suffix wins
		"other.org":           {"default", true},   // default
	}
	for host, want := range cases {
		got, ok := m.Match(host)
		if ok != want.ok || got != want.val {
			t.Errorf("Match(%q) = (%q,%v), want (%q,%v)", host, got, ok, want.val, want.ok)
		}
	}
}

func TestMatchNoDefault(t *testing.T) {
	m := Build([]Entry[string]{{Pattern: "app.example.com", Value: "x"}})
	if _, ok := m.Match("nope.org"); ok {
		t.Fatal("expected no match without a default route")
	}
}
