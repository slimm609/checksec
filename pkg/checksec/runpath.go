package checksec

import (
	"debug/elf"

	"github.com/slimm609/checksec/v3/pkg/utils"
)

type runpath struct {
	Output string
	Color  string
}

// Detect runpath in binary
func RUNPATH(name string) *runpath {
	res := runpath{}
	file, err := elf.Open(name)
	if err != nil {
		utils.Fatalf("Error opening ELF file: %v", err)
	}
	defer file.Close()

	runpath, _ := file.DynValue(29)
	if len(runpath) == 0 {
		res.Output = "No RUNPATH"
		res.Color = "green"
	} else {
		res.Output = "RUNPATH"
		res.Color = "red"
	}
	return &res
}
