package checksec

import (
	"debug/elf"
)

// Detect runpath in binary
func RUNPATH(file *elf.File) *Result {
	paths, _ := file.DynString(elf.DT_RUNPATH)
	r := summarizeRunpath("RUNPATH", paths)
	return &r
}
