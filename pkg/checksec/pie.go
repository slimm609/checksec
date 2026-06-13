package checksec

import (
	"debug/elf"
)

func PIE(name string, binary *elf.File) *Result {
	switch binary.Type {
	case elf.ET_DYN:
		return &Result{Value: "PIE Enabled", Status: StatusGood}
	case elf.ET_REL:
		return &Result{Value: "REL", Status: StatusWarn}
	default:
		return &Result{Value: "PIE Disabled", Status: StatusBad}
	}
}
