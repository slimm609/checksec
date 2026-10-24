package macho

import (
	dm "debug/macho"
	"fmt"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Symbols counts defined, non-stab symtab entries. Imports are excluded so a
// stripped executable that still imports libSystem reports No Symbols.
func Symbols(f *dm.File) *checksec.Result {
	n := definedSymbolCount(f)
	if n == 0 {
		return &checksec.Result{Value: "No Symbols", Status: checksec.StatusGood}
	}
	return &checksec.Result{Value: fmt.Sprintf("%d symbols", n), Status: checksec.StatusBad}
}
