package checksec

import (
	"debug/elf"
)

func RPATH(file *elf.File) *Result {
	rpath, _ := file.DynValue(elf.DT_RPATH)
	if len(rpath) == 0 {
		return &Result{Value: "No RPATH", Status: StatusGood}
	}
	return &Result{Value: "RPATH", Status: StatusBad}
}
