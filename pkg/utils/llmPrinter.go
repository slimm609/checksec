package utils

import (
	"fmt"
	"io"

	"github.com/slimm609/checksec/v3/pkg/checksec"
	"github.com/slimm609/checksec/v3/pkg/exploit"
	"github.com/slimm609/checksec/v3/pkg/knowledge"
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

// presentCheckIDs returns the check ids present across all reports in canonical
// FileFields order, plus a set of ids that are non-good in at least one report.
func presentCheckIDs(reports []FileReport) ([]string, map[string]bool) {
	seen := map[string]bool{}
	nonGood := map[string]bool{}
	var ids []string
	for _, f := range FileFields {
		for _, r := range reports {
			res, ok := r.Checks[f.Key]
			if !ok {
				continue
			}
			if !seen[f.Key] {
				seen[f.Key] = true
				ids = append(ids, f.Key)
			}
			if res.Status != checksec.StatusGood {
				nonGood[f.Key] = true
			}
		}
	}
	return ids, nonGood
}

// writeLLMTarget emits one target block: header + one terse row per present
// check, in canonical FileFields order.
func writeLLMTarget(w io.Writer, r FileReport) {
	fmt.Fprintf(w, "## Target: %s\n", r.Name)
	for _, f := range FileFields {
		res, ok := r.Checks[f.Key]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "- [%s] %s = %s\n", sevGlyph(res.Status), f.Key, res.Value)
	}
	fmt.Fprintln(w)
}

// writeLLMKnowledge emits the one-per-run "what each check means" block. The
// Fix clause is included only for checks non-good in at least one target.
func writeLLMKnowledge(w io.Writer, reports []FileReport) {
	ids, nonGood := presentCheckIDs(reports)
	fmt.Fprintln(w, "## Checks present here (meaning + fix)")
	for _, c := range knowledge.Present(ids) {
		line := fmt.Sprintf("- %-14s %s", c.ID, c.Meaning)
		if c.Remediation != "" && nonGood[c.ID] {
			line += " Fix: " + c.Remediation + "."
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}

// writeLLMExploit renders the exploitability verdicts inline in llm format.
func writeLLMExploit(w io.Writer, r *exploit.Report) {
	if r == nil {
		return
	}
	fmt.Fprintln(w, "### Exploitability  (static; mitigation-obstruction, not proof)")
	for _, v := range r.Verdicts {
		cite := ""
		if len(v.Citations) > 0 {
			cite = v.Citations[0].Value
		}
		fmt.Fprintf(w, "- %-10s %-22s %s\n", v.Tier.String(), v.RuleID, cite)
	}
	if r.Bar != "" {
		fmt.Fprintf(w, "- Bar: %s\n", r.Bar)
	}
	fmt.Fprintln(w)
}

// writeLLM assembles the full "llm" output format: an optional grounding
// preamble, the shared knowledge block, and one target section (plus an
// exploitability sub-block, when present) per report.
func writeLLM(w io.Writer, reports []FileReport, opts PrintOptions) {
	hasExploit := false
	for _, r := range reports {
		if r.Exploitability != nil {
			hasExploit = true
			break
		}
	}

	if !opts.LLMNoPreamble {
		writeLLMPreamble(w, hasExploit)
	}
	writeLLMKnowledge(w, reports)
	for _, r := range reports {
		writeLLMTarget(w, r)
		if r.Exploitability != nil {
			writeLLMExploit(w, r.Exploitability)
		}
	}
}
