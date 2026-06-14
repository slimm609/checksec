package checksec

import (
	"debug/elf"
	"strings"
)

// selfrandoSectionMarker is the section-name fragment selfrando's linker
// plugin emits (typically ".txtrp"). checksec.bash:759 matches by substring.
const selfrandoSectionMarker = "txtrp"

func hasSelfrandoSection(file *elf.File) bool {
	for _, s := range file.Sections {
		if strings.Contains(s.Name, selfrandoSectionMarker) {
			return true
		}
	}
	return false
}

// Selfrando reports whether the binary was linked with selfrando (load-time
// function reordering). Absence is StatusInfo, not StatusBad — selfrando is an
// optional hardening, not a baseline expectation.
func Selfrando(file *elf.File) *Result {
	if hasSelfrandoSection(file) {
		return &Result{Value: "Enabled", Status: StatusGood}
	}
	return &Result{Value: "No Selfrando", Status: StatusInfo}
}
