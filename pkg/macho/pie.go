package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// PIE reads MH_PIE from the header. Dylibs and bundles are always position
// independent, so they report DSO like ELF shared objects do.
func PIE(f *dm.File) *checksec.Result {
	switch f.Type {
	case dm.TypeExec:
		if f.Flags&dm.FlagPIE != 0 {
			return &checksec.Result{Value: "PIE Enabled", Status: checksec.StatusGood}
		}
		return &checksec.Result{Value: "PIE Disabled", Status: checksec.StatusBad}
	case dm.TypeDylib, dm.TypeBundle:
		return &checksec.Result{Value: "DSO", Status: checksec.StatusInfo}
	case dm.TypeObj:
		return &checksec.Result{Value: "Object", Status: checksec.StatusWarn}
	}
	return &checksec.Result{Value: "N/A", Status: checksec.StatusNA}
}
