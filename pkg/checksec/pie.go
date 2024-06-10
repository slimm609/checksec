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
	if binary.Type == elf.ET_DYN {
		res.Color = "green"
		res.Output = "PIE Enabled"
		return &res
	}

	res.Color = "red"
	res.Output = "PIE Disabled"
	return &res
}
