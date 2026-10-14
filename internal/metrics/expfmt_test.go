package metrics

import (
	"math"
	"testing"
)

func TestWriteFormat(t *testing.T) {
	fams := []Family{
		{Name: "b_total", Help: "B help.", Type: Counter, Samples: []Sample{
			{Labels: []Label{{"route", "z.example.com"}}, Value: 2},
			{Labels: []Label{{"route", "a.example.com"}}, Value: 1},
		}},
		{Name: "a_gauge", Help: "A help.", Type: Gauge, Samples: []Sample{{Value: 1.5}}},
		{Name: "empty", Help: "Never written.", Type: Gauge},
	}
	got := string(Encode(fams))
	want := `# HELP a_gauge A help.
# TYPE a_gauge gauge
a_gauge 1.5
# HELP b_total B help.
# TYPE b_total counter
b_total{route="a.example.com"} 1
b_total{route="z.example.com"} 2
`
	if got != want {
		t.Fatalf("output mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteDoesNotReorderInput(t *testing.T) {
	fams := []Family{{Name: "z", Type: Gauge, Samples: []Sample{{Value: 1}}}, {Name: "a", Type: Gauge, Samples: []Sample{{Value: 1}}}}
	_ = Encode(fams)
	if fams[0].Name != "z" {
		t.Fatal("Write must not sort the caller's slice in place")
	}
}

func TestFormatLabelsEscapesAndSkipsEmpty(t *testing.T) {
	got := formatLabels([]Label{{"empty", ""}, {"v", "a\"b\\c\nd"}, {"w", "x"}})
	want := `{v="a\"b\\c\nd",w="x"}`
	if got != want {
		t.Fatalf("formatLabels = %s, want %s", got, want)
	}
	if got := formatLabels([]Label{{"only", ""}}); got != "" {
		t.Fatalf("all-empty labels should render nothing, got %q", got)
	}
}

func TestEscapeHelp(t *testing.T) {
	if got := escapeHelp("a\\b\nc\"d"); got != `a\\b\nc"d` {
		t.Fatalf("escapeHelp = %q", got)
	}
}

func TestFormatValue(t *testing.T) {
	cases := map[float64]string{
		0: "0", 42: "42", -7: "-7", 1.5: "1.5", 180092658: "180092658",
		1 << 52: "4503599627370496", 1e21: "1e+21", 1760000000.25: "1.76000000025e+09",
		math.Inf(1): "+Inf", math.Inf(-1): "-Inf",
	}
	for v, want := range cases {
		if got := formatValue(v); got != want {
			t.Errorf("formatValue(%v) = %q, want %q", v, got, want)
		}
	}
	if got := formatValue(math.NaN()); got != "NaN" {
		t.Errorf("formatValue(NaN) = %q", got)
	}
}
