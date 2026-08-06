package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/slimm609/checksec/v3/pkg/exploit"
)

func TestRenderChainHypothesis(t *testing.T) {
	r := &exploit.Report{Verdicts: []exploit.Verdict{
		{RuleID: "stack-bof-overwrite", Tier: exploit.TierViable, Technique: "Stack overflow",
			Citations: []exploit.Citation{{Kind: "import", Value: "gets"}}},
		{RuleID: "ret2plt", Tier: exploit.TierViable, Technique: "ret2plt → system",
			Citations: []exploit.Citation{{Kind: "import", Value: "system@plt"}}},
	}}
	var buf bytes.Buffer
	RenderChain(&buf, r)
	out := buf.String()
	if !strings.Contains(strings.ToLower(out), "hypothesis") {
		t.Errorf("chain must be labeled hypothesis:\n%s", out)
	}
	if !strings.Contains(out, "stack-bof-overwrite") || !strings.Contains(out, "ret2plt") {
		t.Errorf("chain missing steps:\n%s", out)
	}
}

func TestRenderChainNoneWhenNoHijack(t *testing.T) {
	r := &exploit.Report{Verdicts: []exploit.Verdict{
		{RuleID: "shellcode-injection", Tier: exploit.TierBlocked},
	}}
	var buf bytes.Buffer
	RenderChain(&buf, r)
	if !strings.Contains(strings.ToLower(buf.String()), "no consistent chain") {
		t.Errorf("expected no-chain message:\n%s", buf.String())
	}
}
