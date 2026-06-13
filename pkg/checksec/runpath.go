package checksec

import (
	"debug/elf"
)

// Detect runpath in binary
func RUNPATH(file *elf.File) *Result {
	runpath, _ := file.DynValue(elf.DT_RUNPATH)
	if len(runpath) == 0 {
		return &Result{Value: "No RUNPATH", Status: StatusGood}
	}
	return &Result{Value: "RUNPATH", Status: StatusBad}
}
