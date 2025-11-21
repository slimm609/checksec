package checksec

import (
	"debug/elf"

	"github.com/slimm609/checksec/v3/pkg/output"
)

type rpath struct {
	Output string
	Color  string
}

func RPATH(name string) *rpath {
	res := rpath{}
	file, err := elf.Open(name)
	if err != nil {
		output.Fatalf("Error opening ELF file: %v", err)
	}
	defer file.Close()

	rpath, _ := file.DynValue(15)
	if len(rpath) == 0 {
		res.Output = "No RPATH"
		res.Color = "green"
	} else {
		res.Output = "RPATH"
		res.Color = "red"
	}
	return &res
}
