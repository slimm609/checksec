// pkg/macho/sanitizers.go
package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// Sanitizers reuses the ELF classifier over Darwin-spelled symbol names.
func Sanitizers(f *dm.File) *checksec.Result {
	v := checksec.ClassifySanitizers(allSymbolNames(f))
	if v == "None" {
		return &checksec.Result{Value: v, Status: checksec.StatusInfo}
	}
	return &checksec.Result{Value: v, Status: checksec.StatusGood}
}
