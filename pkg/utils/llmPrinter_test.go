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

func TestKnowledgeBlockGroundsOnceAndOmitsFixForGreen(t *testing.T) {
	reports := []FileReport{
		{Name: "a", Checks: map[string]checksec.Result{
			"nx":  {Value: "NX enabled", Status: checksec.StatusGood},
			"pie": {Value: "No PIE", Status: checksec.StatusBad},
		}},
		{Name: "b", Checks: map[string]checksec.Result{
			"nx":  {Value: "NX enabled", Status: checksec.StatusGood},
			"pie": {Value: "PIE Enabled", Status: checksec.StatusGood},
		}},
	}
	var buf bytes.Buffer
	writeLLMKnowledge(&buf, reports)
	out := buf.String()
	// pie is non-good in report "a" → Fix present. nx is good everywhere → no Fix.
	if !strings.Contains(out, "Fix: `-fPIE -pie`") {
		t.Errorf("pie fix must appear:\n%s", out)
	}
	nxLine := lineContaining(out, "- nx ")
	if strings.Contains(nxLine, "Fix:") {
		t.Errorf("green-everywhere nx must omit Fix, got: %q", nxLine)
	}
	// grounded once: only a single "## Checks present" header
	if strings.Count(out, "## Checks present") != 1 {
		t.Errorf("knowledge block must appear exactly once:\n%s", out)
	}
}

func lineContaining(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}
