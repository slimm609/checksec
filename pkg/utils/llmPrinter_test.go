package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

func TestSevGlyph(t *testing.T) {
	cases := []struct {
		status checksec.Status
		want   string
	}{
		{checksec.StatusGood, "ok"},
		{checksec.StatusWarn, "~"},
		{checksec.StatusBad, "!"},
		{checksec.StatusError, "!"},
		{checksec.StatusInfo, "i"},
		{checksec.StatusNA, "i"},
	}

	for _, tc := range cases {
		if got := sevGlyph(tc.status); got != tc.want {
			t.Errorf("sevGlyph(%v) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestPreambleDirective(t *testing.T) {
	var buf bytes.Buffer
	writeLLMPreamble(&buf, false)
	out := buf.String()
	if !strings.Contains(out, "AUTHORITATIVE") {
		t.Errorf("preamble must assert authority:\n%s", out)
	}
	if !strings.Contains(out, "[!]") || !strings.Contains(out, "[ok]") {
		t.Errorf("preamble must include severity legend:\n%s", out)
	}
	if strings.Contains(out, "Exploitability entries") {
		t.Error("epistemics line must be absent without exploit data")
	}
}

func TestPreambleExploitLine(t *testing.T) {
	var buf bytes.Buffer
	writeLLMPreamble(&buf, true)
	if !strings.Contains(buf.String(), "Exploitability entries") {
		t.Error("epistemics line must appear when exploit data present")
	}
}
