package checksec

import (
	"debug/elf"
)

type nx struct {
	Output string
	Color  string
}

func NX(name string, binary *elf.File) *nx {
	res := nx{}
	if len(binary.Progs) == 0 {
		res.Color = "italic"
		res.Output = "N/A"
		return &res
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X == 0 {
			res.Color = "green"
			res.Output = "NX enabled"
			return &res
		}
	}

	res.Color = "red"
	res.Output = "NX disabled"
	return &res
}
