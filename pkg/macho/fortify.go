// pkg/macho/fortify.go
package macho

import (
	dm "debug/macho"

	"github.com/slimm609/checksec/v3/pkg/checksec"
)

// fortifiable is the ELF list from pkg/checksec/fortify.go reduced to base
// names; Darwin spells the plain call "_strcpy" and the checked one
// "___strcpy_chk".
var fortifiable = []string{
	"memcpy", "memmove", "mempcpy", "memset", "stpcpy", "stpncpy", "strcat",
	"strcpy", "strncat", "strncpy", "snprintf", "sprintf", "vsnprintf",
	"vsprintf", "fprintf", "printf", "vfprintf", "vprintf",
}

func classifyFortify(imports []string) (string, checksec.Status) {
	checked, plain := 0, 0
	for _, name := range imports {
		for _, base := range fortifiable {
			switch {
			case name == "___"+base+"_chk":
				checked++
			case name == "_"+base:
				plain++
			}
		}
	}
	switch {
	case checked > 0:
		return "Yes", checksec.StatusGood
	case plain > 0:
		return "No", checksec.StatusBad
	}
	return "N/A", checksec.StatusNA
}

// FortifySource reports whether any fortifiable libSystem call was routed
// through its ___*_chk variant.
func FortifySource(f *dm.File) *checksec.Result {
	v, s := classifyFortify(importedNames(f))
	return &checksec.Result{Value: v, Status: s}
}
