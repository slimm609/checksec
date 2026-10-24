package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// NX reports whether the image asked for an executable stack
// (MH_ALLOW_STACK_EXECUTION, set by -Wl,-allow_stack_execute).
func NX(f *dm.File) *checksec.Result {
	if f.Flags&dm.FlagAllowStackExecution != 0 {
		return &checksec.Result{Value: "NX disabled", Status: checksec.StatusBad}
	}
	return &checksec.Result{Value: "NX enabled", Status: checksec.StatusGood}
}
