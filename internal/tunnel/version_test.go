package tunnel

import (
	"bytes"
	"testing"
)

func TestPreambleCarriesEdgeVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePreamble(&buf, Preamble{ConnID: "c", Host: "h", EdgeVersion: "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPreamble(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if p.EdgeVersion != "v1.2.3" {
		t.Fatalf("EdgeVersion = %q, want v1.2.3", p.EdgeVersion)
	}
}
