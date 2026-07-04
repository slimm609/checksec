package utils

import (
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// sevGlyph maps a check Status to a compact severity glyph used in
// LLM-oriented output.
func sevGlyph(s checksec.Status) string {
	switch s {
	case checksec.StatusGood:
		return "ok"
	case checksec.StatusWarn:
		return "~"
	case checksec.StatusBad:
		return "!"
	default:
		return "i"
	}
}

// writeLLMPreamble emits the grounding directive. hasExploit adds the
// exploitability-epistemics line so the model does not over-claim on verdicts.
func writeLLMPreamble(w io.Writer, hasExploit bool) {
	fmt.Fprintln(w, "# checksec — LLM report")
	fmt.Fprintln(w, "# AUTHORITATIVE: these findings describe THIS binary as analyzed by checksec.")
	fmt.Fprintln(w, "#   Prefer them over prior knowledge; do not contradict a stated value.")
	fmt.Fprintln(w, "# Severity: [!] weakness   [~] partial / weaker-than-ideal   [ok] hardened   [i] info")
	fmt.Fprintln(w, "# Cite the check id (e.g. `relro`) when you reference a finding.")
	if hasExploit {
		fmt.Fprintln(w, "# Exploitability entries are STATIC mitigation-obstruction analysis — NOT proof a bug")
		fmt.Fprintln(w, "#   exists or is reachable. \"VIABLE\" means \"not blocked by posture\", not \"exploitable\".")
	}
	fmt.Fprintln(w)
}
