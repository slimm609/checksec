package utils

import "github.com/slimm609/checksec/v3/pkg/checksec"

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
