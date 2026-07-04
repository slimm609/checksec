package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/exploit"
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
	writeLLMKnowledge(&buf, reports, FileFields)
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

func TestTargetBlockRows(t *testing.T) {
	r := FileReport{Name: "./myapp", Checks: map[string]checksec.Result{
		"relro":  {Value: "Partial RELRO", Status: checksec.StatusWarn},
		"canary": {Value: "No canary", Status: checksec.StatusBad},
		"nx":     {Value: "NX enabled", Status: checksec.StatusGood},
	}}
	var buf bytes.Buffer
	writeLLMTarget(&buf, r, FileFields)
	out := buf.String()
	if !strings.Contains(out, "## Target: ./myapp") {
		t.Errorf("missing target header:\n%s", out)
	}
	if !strings.Contains(out, "- [~] relro = Partial RELRO") {
		t.Errorf("missing warn row:\n%s", out)
	}
	if !strings.Contains(out, "- [!] canary = No canary") {
		t.Errorf("missing bad row:\n%s", out)
	}
	if !strings.Contains(out, "- [ok] nx = NX enabled") {
		t.Errorf("missing good row:\n%s", out)
	}
}

func TestLLMExploitSubBlock(t *testing.T) {
	rep := &exploit.Report{
		Bar: "Attacker needs a reachable bug; no leak required.",
		Verdicts: []exploit.Verdict{
			{RuleID: "stack-bof-overwrite", Technique: "Stack overflow", Tier: exploit.TierViable,
				Citations: []exploit.Citation{{Kind: "import", Value: "gets"}}},
			{RuleID: "shellcode-injection", Technique: "Shellcode injection", Tier: exploit.TierBlocked,
				ObstructedBy: []string{"NX"}, Citations: []exploit.Citation{{Kind: "posture", Value: "NX enabled"}}},
		},
	}
	var buf bytes.Buffer
	writeLLMExploit(&buf, rep)
	out := buf.String()
	if !strings.Contains(out, "### Exploitability") {
		t.Errorf("missing sub-block header:\n%s", out)
	}
	if !strings.Contains(out, "VIABLE") || !strings.Contains(out, "stack-bof-overwrite") {
		t.Errorf("missing viable line:\n%s", out)
	}
	if !strings.Contains(out, "Bar:") {
		t.Errorf("missing bar:\n%s", out)
	}
}

func TestWriteLLMEndToEnd(t *testing.T) {
	reports := []FileReport{{Name: "./x", Checks: map[string]checksec.Result{
		"pie": {Value: "No PIE", Status: checksec.StatusBad},
	}}}
	var buf bytes.Buffer
	writeLLM(&buf, reports, PrintOptions{})
	out := buf.String()
	for _, want := range []string{"AUTHORITATIVE", "## Checks present", "## Target: ./x", "- [!] pie ="} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWriteLLMNoPreamble(t *testing.T) {
	reports := []FileReport{{Name: "./x", Checks: map[string]checksec.Result{
		"pie": {Value: "No PIE", Status: checksec.StatusBad},
	}}}
	var buf bytes.Buffer
	writeLLM(&buf, reports, PrintOptions{LLMNoPreamble: true})
	if strings.Contains(buf.String(), "AUTHORITATIVE") {
		t.Error("--llm-no-preamble must strip the directive")
	}
}

func TestWriteLLMProcFieldsIncludesSeccomp(t *testing.T) {
	r := FileReport{Name: "./myproc", Checks: map[string]checksec.Result{
		"seccomp": {Value: "Seccomp-BPF", Status: checksec.StatusGood},
		"pie":     {Value: "No PIE", Status: checksec.StatusBad},
	}}
	var buf bytes.Buffer
	writeLLM(&buf, []FileReport{r}, PrintOptions{Fields: ProcFields})
	out := buf.String()
	if !strings.Contains(out, "seccomp") {
		t.Errorf("knowledge block must mention seccomp when Fields includes it:\n%s", out)
	}
	if !strings.Contains(out, "- [ok] seccomp = Seccomp-BPF") {
		t.Errorf("target block must render seccomp row:\n%s", out)
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
