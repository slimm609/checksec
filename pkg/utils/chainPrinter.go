package utils

import (
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/exploit"
)

// RenderChain emits a labeled hypothesis chain: a VIABLE control-flow-hijack
// step plus a mutually-consistent VIABLE payload step. Never presented as fact.
func RenderChain(w io.Writer, r *exploit.Report) {
	if r == nil {
		return
	}
	hijack := findVerdict(r, "stack-bof-overwrite", exploit.TierViable)
	payload := firstViablePayload(r)
	if hijack == nil || payload == nil {
		fmt.Fprintln(w, "Suggested chain: no consistent chain at current tier.")
		return
	}
	fmt.Fprintln(w, "Suggested chain (hypothesis):")
	fmt.Fprintf(w, "  1. %s [%s: %s]\n", hijack.Technique, hijack.RuleID, hijack.Tier)
	fmt.Fprintf(w, "  2. %s [%s: %s]\n", payload.Technique, payload.RuleID, payload.Tier)
}

func findVerdict(r *exploit.Report, id string, tier exploit.Tier) *exploit.Verdict {
	for i := range r.Verdicts {
		if r.Verdicts[i].RuleID == id && r.Verdicts[i].Tier == tier {
			return &r.Verdicts[i]
		}
	}
	return nil
}

func firstViablePayload(r *exploit.Report) *exploit.Verdict {
	for _, id := range []string{"ret2plt", "got-overwrite", "shellcode-injection", "ret2libc"} {
		if v := findVerdict(r, id, exploit.TierViable); v != nil {
			return v
		}
	}
	return nil
}
