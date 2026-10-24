package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Fixups is the RELRO analogue. Chained fixups (and bind-at-load) leave no
// writable lazy-pointer table for an attacker to overwrite; a __la_symbol_ptr
// section means lazy binding through a writable table.
func Fixups(f *dm.File) *checksec.Result {
	if f.Type == dm.TypeObj {
		return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
	}
	if _, ok := findLoad(f, lcDyldChainedFixups); ok {
		return &checksec.Result{Value: "Chained fixups", Status: checksec.StatusGood}
	}
	if f.Flags&dm.FlagBindAtLoad != 0 {
		return &checksec.Result{Value: "Bind at load", Status: checksec.StatusGood}
	}
	if f.Section("__la_symbol_ptr") != nil {
		return &checksec.Result{Value: "Lazy binding", Status: checksec.StatusWarn}
	}
	return &checksec.Result{Value: "Bind at load", Status: checksec.StatusGood}
}
