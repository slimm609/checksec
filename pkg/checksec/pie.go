package checksec

import (
	"debug/elf"
)

type pie struct {
	Output string
	Color  string
}

func PIE(name string, binary *elf.File) *pie {
	res := pie{}
	switch binary.Type {
	case elf.ET_DYN:
		res.Color = "green"
		res.Output = "PIE Enabled"
	case elf.ET_REL:
		res.Color = "yellow"
		res.Output = "REL"
	default:
		res.Color = "red"
		res.Output = "PIE Disabled"
	}

	return &res
}
