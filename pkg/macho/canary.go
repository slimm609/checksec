package macho

import (
	dm "debug/macho"
	"strings"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// canarySymbols are the Darwin spellings (leading underscore) of the
// stack-protector runtime symbols.
var canarySymbols = []string{"___stack_chk_fail", "___stack_chk_guard"}

// Canary looks for the stack-protector runtime among the image's symbols.
func Canary(f *dm.File) *checksec.Result {
	for _, name := range allSymbolNames(f) {
		for _, c := range canarySymbols {
			if strings.HasPrefix(name, c) {
				return &checksec.Result{Value: "Canary Found", Status: checksec.StatusGood}
			}
		}
	}
	return &checksec.Result{Value: "No Canary Found", Status: checksec.StatusBad}
}
