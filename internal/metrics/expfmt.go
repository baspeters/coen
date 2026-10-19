// Package metrics exposes coen's live counters in the Prometheus text
// exposition format (version 0.0.4) on an opt-in HTTP listener. The format is
// written directly, without a client library, to keep the dependency set small.
package metrics

import (
	"bytes"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Type is a Prometheus metric type.
type Type string

const (
	Counter Type = "counter"
	Gauge   Type = "gauge"
)

// Label is one name/value pair on a sample.
type Label struct {
	Name, Value string
}

// Sample is one time series value in a family.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a named metric with its help text, type, and samples.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

// Encode renders families in the text exposition format. Families are written
// in name order and samples in label order, so output is stable across scrapes.
// A family with no samples is skipped entirely.
func Encode(families []Family) []byte {
	sorted := append([]Family(nil), families...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b bytes.Buffer
	for _, f := range sorted {
		if len(f.Samples) == 0 {
			continue
		}
		b.WriteString("# HELP " + f.Name + " " + escapeHelp(f.Help) + "\n")
		b.WriteString("# TYPE " + f.Name + " " + string(f.Type) + "\n")
		lines := make([]string, 0, len(f.Samples))
		for _, smp := range f.Samples {
			lines = append(lines, f.Name+formatLabels(smp.Labels)+" "+formatValue(smp.Value)+"\n")
		}
		sort.Strings(lines)
		for _, ln := range lines {
			b.WriteString(ln)
		}
	}
	return b.Bytes()
}

// formatLabels renders {a="x",b="y"}, omitting empty values (Prometheus treats
// an empty label value as an absent label) and returning "" when none remain.
func formatLabels(labels []Label) string {
	var b strings.Builder
	n := 0
	for _, l := range labels {
		if l.Value == "" {
			continue
		}
		if n == 0 {
			b.WriteByte('{')
		} else {
			b.WriteByte(',')
		}
		b.WriteString(l.Name)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(l.Value))
		b.WriteByte('"')
		n++
	}
	if n > 0 {
		b.WriteByte('}')
	}
	return b.String()
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	// Counters and gauges here are whole numbers; print them exactly rather than
	// in exponent form (1.80092658e+08), which is valid but hard to read. Below
	// 2^53 a float64 holds every integer exactly.
	if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
