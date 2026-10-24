package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Restrict reports the legacy __RESTRICT,__restrict section that tells dyld to
// ignore DYLD_* variables. Superseded by the hardened runtime, hence info.
func Restrict(f *dm.File) *checksec.Result {
	for _, s := range f.Sections {
		if s.Seg == "__RESTRICT" && s.Name == "__restrict" {
			return &checksec.Result{Value: "Enabled", Status: checksec.StatusGood}
		}
	}
	return &checksec.Result{Value: "No Restrict", Status: checksec.StatusInfo}
}
